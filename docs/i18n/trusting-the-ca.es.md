<!-- source-sha256: 51e546526752332fcfc280e7dff9c74d662f180be9dc12f325b1f7754935dbb2 -->
# Confiar en una autoridad certificadora de MiniCA

Un cliente solo acepta los certificados emitidos por MiniCA cuando confía en
la CA emisora. Esta página reúne las instrucciones para las plataformas y
herramientas más habituales. Todo parte de las dos descargas públicas que
tiene toda CA (no requieren inicio de sesión):

| Descarga | URL | Para qué sirve |
| --- | --- | --- |
| Certificado de la CA (PEM) | `https://ca.example.com/minica/<ca-id>/download` | todo excepto Java |
| Almacén de confianza de la CA (PKCS#12, contraseña `changeit`) | `https://ca.example.com/minica/download/ca/<ca-id>/truststore` | aplicaciones Java / JVM |

Ambas también están enlazadas desde el índice público de CA en `https://ca.example.com/minica/`
y desde la página de la CA. El archivo se nombra según el nombre común de la CA, p. ej.
`Homelab_CA.pem`; en los ejemplos siguientes se llama `minica-ca.pem` / `minica-ca.crt`.

```sh
curl -fsSLo minica-ca.pem https://ca.example.com/minica/<ca-id>/download
openssl x509 -in minica-ca.pem -noout -subject -dates -fingerprint -sha256   # check what you got
```

En los clientes solo se instala el **certificado de la CA**, nunca una clave
privada. Si la CA es una intermedia, instale en su lugar su raíz (o también).

## Sistemas operativos

### Debian / Ubuntu

```sh
sudo cp minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt   # must end in .crt, PEM content
sudo update-ca-certificates
```

Esto añade la CA a `/etc/ssl/certs/ca-certificates.crt`, que usan curl, wget,
Python, Go, Node (con `NODE_EXTRA_CA_CERTS` o `--use-openssl-ca`), apt y la
mayoría de los demás programas del sistema. `/usr/local/share/ca-certificates/`
es el lugar adecuado para las incorporaciones locales; `/usr/share/ca-certificates/` pertenece
al paquete de la distribución.

### RHEL / Fedora / CentOS Stream / Alma / Rocky

```sh
sudo cp minica-ca.pem /etc/pki/ca-trust/source/anchors/minica-ca.pem
sudo update-ca-trust
```

### Alpine

```sh
sudo cp minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
sudo update-ca-certificates
```

(Ejecute antes `apk add ca-certificates` si falta `update-ca-certificates`.)

### Arch Linux

```sh
sudo trust anchor --store minica-ca.pem
```

### macOS

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain minica-ca.pem
```

O bien haga doble clic en el archivo, añádalo al llavero *Sistema* en Acceso a Llaveros,
ábralo y establezca *Al usar este certificado* en *Confiar siempre*. Safari y
Chrome usan el llavero; Firefox necesita el paso adicional que se describe más abajo.

### Windows

Como administrador (PowerShell):

```powershell
Import-Certificate -FilePath .\minica-ca.pem -CertStoreLocation Cert:\LocalMachine\Root
```

o `certutil -addstore -f Root minica-ca.pem`, o haga doble clic → *Instalar
certificado* → *Equipo local* → *Colocar todos los certificados en el siguiente
almacén* → *Entidades de certificación raíz de confianza*. Edge, Chrome y
.NET/PowerShell usan este almacén; Firefox necesita el paso adicional que se describe más abajo.

### Android

Android solo instala archivos DER o PEM con nombre `.crt`/`.cer`:

```sh
openssl x509 -in minica-ca.pem -outform DER -out minica-ca.crt
```

Cópielo al teléfono y luego vaya a *Ajustes → Seguridad → Cifrado y credenciales →
Instalar un certificado → Certificado de CA*. Android 11+ advierte de que el
certificado debe instalarse desde Ajustes; esa es la ruta indicada arriba.
Chrome y la mayoría de las aplicaciones confiarán entonces en él, pero no lo harán las aplicaciones que fijan certificados (pinning) o incluyen
su propio almacén de confianza (ni algunas que usan su propia pila de red).

### iOS / iPadOS

Abra el `.pem` en el dispositivo (AirDrop, Mail, Archivos) → *Ajustes → Perfil
descargado → Instalar* y luego actívelo en *Ajustes → General → Información →
Ajustes de confianza de certificados*.

## Navegadores

Chrome, Edge y Safari usan el almacén del sistema operativo, por lo que los pasos anteriores
bastan. **Firefox** mantiene su propio almacén salvo que se le indique otra cosa:

- Preferencias → Privacidad y seguridad → Certificados → *Ver certificados* →
  *Autoridades* → *Importar* → marque *Confiar en esta CA para identificar sitios web*; o
- establezca `security.enterprise_roots.enabled` en `true` en `about:config` para que
  Firefox use el almacén del sistema de Windows / macOS; o
- en Linux, importe en la base de datos NSS del perfil:
  `certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.mozilla/firefox/<profile>` (`certutil` procede de `libnss3-tools` / `nss-tools`).

Chromium en Linux también tiene un almacén NSS para las CA instaladas por el usuario:
`certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.pki/nssdb`.

## Herramientas de línea de comandos y lenguajes

### curl

```sh
curl --cacert minica-ca.pem https://intranet.example.com/
export CURL_CA_BUNDLE=/path/to/minica-ca.pem     # for a shell session
```

Tras instalar la CA en el almacén del sistema (arriba) no se necesita ninguna opción.
`CURL_CA_BUNDLE` *reemplaza* el paquete, así que apúntelo a un archivo que contenga
también las CA públicas si necesita ambas (p. ej., añada el PEM de MiniCA a una copia
de `/etc/ssl/certs/ca-certificates.crt`).

### wget

```sh
wget --ca-certificate=minica-ca.pem https://intranet.example.com/
echo "ca_certificate = /path/to/minica-ca.pem" >> ~/.wgetrc
```

### Python

`urllib`, `http.client` y el módulo `ssl` usan las rutas predeterminadas de OpenSSL,
es decir, el almacén del sistema, y respetan `SSL_CERT_FILE` / `SSL_CERT_DIR`. La
biblioteca `requests` (y todo lo construido sobre ella, incluido `pip`) usa en cambio el
paquete `certifi`:

```sh
export REQUESTS_CA_BUNDLE=/path/to/minica-ca.pem   # requests; replaces the bundle
export SSL_CERT_FILE=/path/to/minica-ca.pem        # ssl / urllib / httpx
pip config set global.cert /path/to/minica-ca.pem  # pip
```

Para conservar también las CA públicas, añada el PEM de MiniCA a una copia del paquete
de certifi (`python -m certifi` muestra su ruta) y apunte las variables a la
copia. `pip install pip-system-certs` o `truststore` hace que requests use en su lugar el
almacén del sistema operativo.

### Java / JVM (Kafka, Elasticsearch, Jenkins, ...)

La descarga del almacén de confianza de la CA es un almacén PKCS#12 listo para usar (contraseña
`changeit`, con la CA guardada como `trustedCertEntry`):

```sh
curl -fsSLo minica-truststore.p12 https://ca.example.com/minica/download/ca/<ca-id>/truststore
java -Djavax.net.ssl.trustStore=minica-truststore.p12 \
     -Djavax.net.ssl.trustStorePassword=changeit \
     -Djavax.net.ssl.trustStoreType=PKCS12 -jar app.jar
```

Ese almacén de confianza contiene *solo* la CA de MiniCA. Para añadir la CA al almacén
predeterminado del JDK (de modo que las CA públicas sigan funcionando):

```sh
keytool -importcert -trustcacerts -noprompt -alias minica \
  -file minica-ca.pem -cacerts -storepass changeit
```

Los clientes de Kafka usan `ssl.truststore.location=minica-truststore.p12`,
`ssl.truststore.password=changeit`, `ssl.truststore.type=PKCS12`.

### Go

Go usa el almacén del sistema (`crypto/x509` lee `/etc/ssl/certs` en Linux) y
respeta `SSL_CERT_FILE` / `SSL_CERT_DIR`. Para añadir una CA desde código:

```go
pool, _ := x509.SystemCertPool()
pem, _ := os.ReadFile("minica-ca.pem")
pool.AppendCertsFromPEM(pem)
client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
```

### Node.js

```sh
NODE_EXTRA_CA_CERTS=/path/to/minica-ca.pem node app.js
```

Esto *añade* CA a las incluidas con Node. `--use-openssl-ca` hace que Node use el
almacén del sistema en su lugar.

### yt-dlp

yt-dlp es un programa de Python y sigue las reglas de Python: con `certifi`
instalado (el caso habitual) usa el paquete de certifi; si no, el almacén
predeterminado de OpenSSL. Instale la CA en el almacén del sistema y elimine o
evite certifi, o apunte la pila HTTP de yt-dlp a un paquete que contenga ambos:

```sh
cat "$(python3 -m certifi)" minica-ca.pem > ~/.config/yt-dlp/ca-bundle.pem
SSL_CERT_FILE=~/.config/yt-dlp/ca-bundle.pem REQUESTS_CA_BUNDLE=~/.config/yt-dlp/ca-bundle.pem yt-dlp https://media.intranet.example.com/...
```

Evite `--no-check-certificates`; desactiva por completo la verificación.

## Servidores y servicios

### Nginx

Es fácil confundir tres cosas distintas:

- **Servir un certificado emitido por MiniCA.** Descargue el *Bundle* (zip) del
  certificado — `cert.pem`, `cert.key` y `ca.pem` — y use
  ```nginx
  ssl_certificate     /etc/nginx/tls/cert.pem;    # or cat cert.pem ca.pem > fullchain.pem
  ssl_certificate_key /etc/nginx/tls/cert.key;
  ```
  Los clientes necesitarán entonces la CA instalada como se describe en esta página.
- **Nginx como cliente TLS** (como proxy hacia un upstream que presenta un
  certificado de MiniCA):
  ```nginx
  proxy_ssl_verify on;
  proxy_ssl_trusted_certificate /etc/nginx/tls/minica-ca.pem;
  proxy_ssl_name upstream.example.com;
  ```
- **Certificados de cliente (mTLS) emitidos por MiniCA:**
  ```nginx
  ssl_client_certificate /etc/nginx/tls/minica-ca.pem;
  ssl_verify_client on;
  ssl_crl /etc/nginx/tls/minica.crl.pem;   # optional: openssl crl -inform DER -in <crl> -out minica.crl.pem
  ```
  La CRL está en `https://ca.example.com/minica/crl/<ca-id>` (DER).

### Docker

Para una **imagen**, añada la CA en el momento de la compilación para que todas las herramientas de la imagen la vean:

```dockerfile
# Debian/Ubuntu based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN update-ca-certificates
# Alpine based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN apk add --no-cache ca-certificates && update-ca-certificates
```

Para un **contenedor que no puede reconstruir**, monte un paquete que ya contenga
la CA (p. ej., el `/etc/ssl/certs/ca-certificates.crt` del host tras instalar
la CA en el host) sobre el paquete de la imagen, o apunte las herramientas internas hacia él
mediante las variables de entorno indicadas arriba:

```yaml
    environment:
      SSL_CERT_FILE:        /etc/ssl/certs/ca-certificates.crt   # OpenSSL, Python ssl, Go, Ruby
      REQUESTS_CA_BUNDLE:   /etc/ssl/certs/ca-certificates.crt   # Python requests
      CURL_CA_BUNDLE:       /etc/ssl/certs/ca-certificates.crt   # curl
      NODE_EXTRA_CA_CERTS:  /etc/ssl/certs/ca-certificates.crt   # Node.js
    volumes:
      - /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro
```

Las imágenes basadas en distribuciones que guardan el paquete en otra ubicación
(familia RHEL: `/etc/pki/tls/certs/ca-bundle.crt`) necesitan esa ruta en su lugar.

El *daemon* de Docker confía en la CA de un registro privado desde
`/etc/docker/certs.d/<registry:port>/ca.crt`, con independencia del almacén del sistema.

### LLDAP

LLDAP es un servidor: proporciónele un certificado emitido por MiniCA para su
listener LDAPS (descargue el bundle del certificado; la clave es `cert.key`):

```toml
# lldap_config.toml
[ldaps_options]
enabled = true
port = 6360
cert_file = "/data/tls/cert.pem"
key_file = "/data/tls/cert.key"
```

o `LLDAP_LDAPS_OPTIONS__ENABLED=true`, `LLDAP_LDAPS_OPTIONS__CERT_FILE=...`,
`LLDAP_LDAPS_OPTIONS__KEY_FILE=...` en el entorno. Todo cliente LDAP
(Authelia, Nextcloud, Jellyfin, ...) necesita entonces la CA de MiniCA en su propio
almacén de confianza, según las instrucciones anteriores para la plataforma o el lenguaje en que se ejecute.

## Publicar MiniCA a través de Nginx

Con el inicio de sesión propio de MiniCA, basta con un prefijo. MiniCA protege sus páginas privadas por sí mismo y esta guía sigue siendo pública en `/minica/how-to-use`:

```nginx
location /minica/ {
    proxy_pass http://minica:9988;
    include /etc/nginx/snippets/proxy.conf;
}
```

Con SSO (Authelia, oauth2-proxy, ...), el prefijo queda protegido, así que las páginas públicas necesitan una regla propia. Mantén vacías las cabeceras de identidad en esa regla, porque MiniCA confía en ellas cuando llegan desde el proxy:

```nginx
# Public pages: no SSO, client-supplied identity headers removed.
location ~ ^/minica/(how-to-use|lang/[^/]+|[^/]+/download|download/ca/[^/]+/truststore(-password)?|crl/[^/]+)?$ {
    proxy_pass http://minica:9988;
    include /etc/nginx/snippets/proxy.conf;
    proxy_set_header Remote-User "";
    proxy_set_header Remote-Groups "";
}

# Everything else: behind SSO.
include /etc/nginx/snippets/authelia-location.conf;
location /minica/ {
    proxy_pass http://minica:9988;
    include /etc/nginx/snippets/authelia-authrequest.conf;
}
```

## Comprobar que funciona

```sh
openssl s_client -connect intranet.example.com:443 -servername intranet.example.com </dev/null 2>/dev/null | grep "Verify return code"
curl -v https://intranet.example.com/ 2>&1 | grep -E "SSL certificate verify|issuer"
```

`Verify return code: 0 (ok)` significa que el cliente encontró la CA y confía en ella.
