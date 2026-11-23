<!-- source-sha256: 51e546526752332fcfc280e7dff9c74d662f180be9dc12f325b1f7754935dbb2 -->
# Een MiniCA-certificeringsinstantie vertrouwen

Certificaten die door MiniCA zijn uitgegeven, worden door een client pas
geaccepteerd zodra die client de uitgevende CA vertrouwt. Deze pagina bundelt
de recepten voor de gangbare platforms en tools. Alles begint met de twee
openbare downloads die elke CA heeft (geen login nodig):

| Download | URL | Gebruik het voor |
| --- | --- | --- |
| CA-certificaat (PEM) | `https://ca.example.com/minica/<ca-id>/download` | alles behalve Java |
| CA-truststore (PKCS#12, wachtwoord `changeit`) | `https://ca.example.com/minica/download/ca/<ca-id>/truststore` | Java / JVM-applicaties |

Beide zijn ook gelinkt vanaf de openbare CA-index op `https://ca.example.com/minica/`
en vanaf de CA-pagina. Het bestand is vernoemd naar de common name van de CA, bijv.
`Homelab_CA.pem`; in de voorbeelden hieronder heet het `minica-ca.pem` / `minica-ca.crt`.

```sh
curl -fsSLo minica-ca.pem https://ca.example.com/minica/<ca-id>/download
openssl x509 -in minica-ca.pem -noout -subject -dates -fingerprint -sha256   # check what you got
```

Alleen het **CA-certificaat** wordt ooit op clients geïnstalleerd — nooit een
privésleutel. Als de CA een tussenliggende CA is, installeer dan in plaats daarvan
(of ook) de root.

## Besturingssystemen

### Debian / Ubuntu

```sh
sudo cp minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt   # must end in .crt, PEM content
sudo update-ca-certificates
```

Dit voegt de CA toe aan `/etc/ssl/certs/ca-certificates.crt`, dat curl, wget,
Python, Go, Node (met `NODE_EXTRA_CA_CERTS` of `--use-openssl-ca`), apt en
de meeste andere programma's op het systeem gebruiken. `/usr/local/share/ca-certificates/`
is de juiste plek voor lokale toevoegingen; `/usr/share/ca-certificates/` hoort
bij het pakket van de distributie.

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

(Voer eerst `apk add ca-certificates` uit als `update-ca-certificates` ontbreekt.)

### Arch Linux

```sh
sudo trust anchor --store minica-ca.pem
```

### macOS

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain minica-ca.pem
```

Of dubbelklik op het bestand, voeg het toe aan de *Systeem*-sleutelhanger in Sleutelhangertoegang,
open het en stel *Bij gebruik van dit certificaat* in op *Altijd vertrouwen*. Safari en
Chrome gebruiken de sleutelhanger; Firefox heeft de extra stap hieronder nodig.

### Windows

Als beheerder (PowerShell):

```powershell
Import-Certificate -FilePath .\minica-ca.pem -CertStoreLocation Cert:\LocalMachine\Root
```

of `certutil -addstore -f Root minica-ca.pem`, of dubbelklik → *Certificaat
installeren* → *Lokale computer* → *Alle certificaten in het volgende
archief plaatsen* → *Vertrouwde basiscertificeringsinstanties*. Edge, Chrome en
.NET/PowerShell gebruiken dit archief; Firefox heeft de extra stap hieronder nodig.

### Android

Android installeert alleen DER- of PEM-bestanden met een `.crt`/`.cer`-naam:

```sh
openssl x509 -in minica-ca.pem -outform DER -out minica-ca.crt
```

Kopieer het naar de telefoon en ga dan naar *Instellingen → Beveiliging → Versleuteling en inloggegevens →
Een certificaat installeren → CA-certificaat*. Android 11+ waarschuwt dat het
certificaat vanuit Instellingen moet worden geïnstalleerd; dat is het pad hierboven.
Chrome en de meeste apps vertrouwen het dan, maar apps die certificaten pinnen of een
eigen truststore meeleveren (en sommige die een eigen netwerkstack gebruiken) niet.

### iOS / iPadOS

Open de `.pem` op het apparaat (AirDrop, Mail, Bestanden) → *Instellingen → Profiel
gedownload → Installeer*, en schakel het daarna in onder *Instellingen → Algemeen → Info →
Vertrouwensinstellingen voor certificaten*.

## Browsers

Chrome, Edge en Safari gebruiken het archief van het besturingssysteem, dus de stappen hierboven
volstaan. **Firefox** houdt een eigen archief bij tenzij anders ingesteld:

- Voorkeuren → Privacy en beveiliging → Certificaten → *Certificaten bekijken* →
  *Autoriteiten* → *Importeren* → vink *Deze CA vertrouwen voor het identificeren van websites* aan; of
- stel `security.enterprise_roots.enabled` in op `true` in `about:config` zodat
  Firefox het systeemarchief van Windows / macOS gebruikt; of
- importeer op Linux in de NSS-database van het profiel:
  `certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.mozilla/firefox/<profile>` (`certutil` uit `libnss3-tools` / `nss-tools`).

Chromium op Linux heeft ook een NSS-archief voor door gebruikers geïnstalleerde CA's:
`certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.pki/nssdb`.

## Opdrachtregeltools en programmeertalen

### curl

```sh
curl --cacert minica-ca.pem https://intranet.example.com/
export CURL_CA_BUNDLE=/path/to/minica-ca.pem     # for a shell session
```

Na het installeren van de CA in het systeemarchief (zie boven) is geen optie nodig.
`CURL_CA_BUNDLE` *vervangt* de bundel, dus verwijs naar een bestand dat ook de
openbare CA's bevat als u beide nodig hebt (voeg bijv. de MiniCA-PEM toe aan een kopie
van `/etc/ssl/certs/ca-certificates.crt`).

### wget

```sh
wget --ca-certificate=minica-ca.pem https://intranet.example.com/
echo "ca_certificate = /path/to/minica-ca.pem" >> ~/.wgetrc
```

### Python

`urllib`, `http.client` en de `ssl`-module gebruiken de standaardpaden van OpenSSL,
dus het systeemarchief, en respecteren `SSL_CERT_FILE` / `SSL_CERT_DIR`. De
`requests`-bibliotheek (en alles wat erop gebouwd is, inclusief `pip`) gebruikt
in plaats daarvan de `certifi`-bundel:

```sh
export REQUESTS_CA_BUNDLE=/path/to/minica-ca.pem   # requests; replaces the bundle
export SSL_CERT_FILE=/path/to/minica-ca.pem        # ssl / urllib / httpx
pip config set global.cert /path/to/minica-ca.pem  # pip
```

Om ook de openbare CA's te behouden, voegt u de MiniCA-PEM toe aan een kopie van de bundel van certifi
(`python -m certifi` toont het pad) en wijst u de variabelen naar de
kopie. Met `pip install pip-system-certs` of `truststore` gebruikt requests
in plaats daarvan het archief van het besturingssysteem.

### Java / JVM (Kafka, Elasticsearch, Jenkins, ...)

De download van de CA-truststore is een kant-en-klare PKCS#12-truststore (wachtwoord
`changeit`, de CA opgeslagen als `trustedCertEntry`):

```sh
curl -fsSLo minica-truststore.p12 https://ca.example.com/minica/download/ca/<ca-id>/truststore
java -Djavax.net.ssl.trustStore=minica-truststore.p12 \
     -Djavax.net.ssl.trustStorePassword=changeit \
     -Djavax.net.ssl.trustStoreType=PKCS12 -jar app.jar
```

Die truststore bevat *alleen* de MiniCA-CA. Om de CA juist toe te voegen aan het
standaardarchief van de JDK (zodat openbare CA's blijven werken):

```sh
keytool -importcert -trustcacerts -noprompt -alias minica \
  -file minica-ca.pem -cacerts -storepass changeit
```

Kafka-clients gebruiken `ssl.truststore.location=minica-truststore.p12`,
`ssl.truststore.password=changeit`, `ssl.truststore.type=PKCS12`.

### Go

Go gebruikt het systeemarchief (`crypto/x509` leest `/etc/ssl/certs` op Linux) en
respecteert `SSL_CERT_FILE` / `SSL_CERT_DIR`. Een CA toevoegen vanuit code:

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

Dit *voegt toe* aan de meegeleverde CA's van Node. Met `--use-openssl-ca` gebruikt Node
in plaats daarvan het systeemarchief.

### yt-dlp

yt-dlp is een Python-programma en volgt de Python-regels: met `certifi`
geïnstalleerd (het gebruikelijke geval) gebruikt het de bundel van certifi, anders het
standaardarchief van OpenSSL. Installeer de CA in het systeemarchief en verwijder /
omzeil certifi, of wijs de HTTP-stack van yt-dlp naar een bundel die beide bevat:

```sh
cat "$(python3 -m certifi)" minica-ca.pem > ~/.config/yt-dlp/ca-bundle.pem
SSL_CERT_FILE=~/.config/yt-dlp/ca-bundle.pem REQUESTS_CA_BUNDLE=~/.config/yt-dlp/ca-bundle.pem yt-dlp https://media.intranet.example.com/...
```

Vermijd `--no-check-certificates`; het schakelt verificatie volledig uit.

## Servers en diensten

### Nginx

Drie verschillende dingen zijn gemakkelijk te verwarren:

- **Een door MiniCA uitgegeven certificaat aanbieden.** Download de
  *Bundel* (zip) van het certificaat — `cert.pem`, `cert.key` en `ca.pem` — en gebruik
  ```nginx
  ssl_certificate     /etc/nginx/tls/cert.pem;    # or cat cert.pem ca.pem > fullchain.pem
  ssl_certificate_key /etc/nginx/tls/cert.key;
  ```
  Clients hebben dan de CA nodig, geïnstalleerd zoals beschreven op deze pagina.
- **Nginx als TLS-client** (proxyen naar een upstream die een
  MiniCA-certificaat toont):
  ```nginx
  proxy_ssl_verify on;
  proxy_ssl_trusted_certificate /etc/nginx/tls/minica-ca.pem;
  proxy_ssl_name upstream.example.com;
  ```
- **Clientcertificaten (mTLS) uitgegeven door MiniCA:**
  ```nginx
  ssl_client_certificate /etc/nginx/tls/minica-ca.pem;
  ssl_verify_client on;
  ssl_crl /etc/nginx/tls/minica.crl.pem;   # optional: openssl crl -inform DER -in <crl> -out minica.crl.pem
  ```
  De CRL staat op `https://ca.example.com/minica/crl/<ca-id>` (DER).

### Docker

Voeg voor een **image** de CA toe tijdens de build, zodat elke tool in de image hem ziet:

```dockerfile
# Debian/Ubuntu based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN update-ca-certificates
# Alpine based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN apk add --no-cache ca-certificates && update-ca-certificates
```

Voor een **container die u niet kunt herbouwen**, mount u een bundel die de CA al bevat
(bijv. de `/etc/ssl/certs/ca-certificates.crt` van de host na het installeren van
de CA op de host) over de bundel van de image, of wijst u de tools erin ernaar
via de omgevingsvariabelen hierboven:

```yaml
    environment:
      SSL_CERT_FILE:        /etc/ssl/certs/ca-certificates.crt   # OpenSSL, Python ssl, Go, Ruby
      REQUESTS_CA_BUNDLE:   /etc/ssl/certs/ca-certificates.crt   # Python requests
      CURL_CA_BUNDLE:       /etc/ssl/certs/ca-certificates.crt   # curl
      NODE_EXTRA_CA_CERTS:  /etc/ssl/certs/ca-certificates.crt   # Node.js
    volumes:
      - /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro
```

Images op basis van distributies die de bundel elders bewaren
(RHEL-familie: `/etc/pki/tls/certs/ca-bundle.crt`) hebben dat pad nodig.

De Docker-*daemon* vertrouwt de CA van een privéregister vanuit
`/etc/docker/certs.d/<registry:port>/ca.crt`, onafhankelijk van het systeemarchief.

### LLDAP

LLDAP is een server: geef hem een door MiniCA uitgegeven certificaat voor zijn LDAPS-listener
(download de bundel van het certificaat; de sleutel is `cert.key`):

```toml
# lldap_config.toml
[ldaps_options]
enabled = true
port = 6360
cert_file = "/data/tls/cert.pem"
key_file = "/data/tls/cert.key"
```

of `LLDAP_LDAPS_OPTIONS__ENABLED=true`, `LLDAP_LDAPS_OPTIONS__CERT_FILE=...`,
`LLDAP_LDAPS_OPTIONS__KEY_FILE=...` in de omgeving. Elke LDAP-client
(Authelia, Nextcloud, Jellyfin, ...) heeft dan de MiniCA-CA nodig in zijn eigen
trust store, volgens de recepten hierboven voor het platform of de taal waarop hij draait.

## MiniCA publiceren via Nginx

Met de eigen login van MiniCA is één prefix genoeg. MiniCA beveiligt zijn privépagina's zelf, en deze handleiding blijft openbaar op `/minica/how-to-use`:

```nginx
location /minica/ {
    proxy_pass http://minica:9988;
    include /etc/nginx/snippets/proxy.conf;
}
```

Met SSO (Authelia, oauth2-proxy, ...) is de prefix beveiligd, dus de openbare pagina's hebben een eigen regel nodig. Houd de identiteitsheaders op die regel leeg, want MiniCA vertrouwt ze wanneer ze van de proxy komen:

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

## Controleren of het werkt

```sh
openssl s_client -connect intranet.example.com:443 -servername intranet.example.com </dev/null 2>/dev/null | grep "Verify return code"
curl -v https://intranet.example.com/ 2>&1 | grep -E "SSL certificate verify|issuer"
```

`Verify return code: 0 (ok)` betekent dat de client de CA heeft gevonden en vertrouwt.
