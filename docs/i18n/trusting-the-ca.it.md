<!-- source-sha256: 51e546526752332fcfc280e7dff9c74d662f180be9dc12f325b1f7754935dbb2 -->
# Considerare attendibile una autorità di certificazione MiniCA

I certificati emessi da MiniCA vengono accettati da un client solo dopo che
quel client considera attendibile la CA emittente. Questa pagina raccoglie le
procedure per le piattaforme e gli strumenti più comuni. Tutto parte dai due
download pubblici che ogni CA offre (non serve alcun accesso):

| Download | URL | Da usare per |
| --- | --- | --- |
| Certificato CA (PEM) | `https://ca.example.com/minica/<ca-id>/download` | tutto tranne Java |
| Truststore della CA (PKCS#12, password `changeit`) | `https://ca.example.com/minica/download/ca/<ca-id>/truststore` | applicazioni Java / JVM |

Entrambi sono collegati anche dall'indice pubblico delle CA in `https://ca.example.com/minica/`
e dalla pagina della CA. Il file prende il nome dal common name della CA, ad es.
`Homelab_CA.pem`; gli esempi seguenti lo chiamano `minica-ca.pem` / `minica-ca.crt`.

```sh
curl -fsSLo minica-ca.pem https://ca.example.com/minica/<ca-id>/download
openssl x509 -in minica-ca.pem -noout -subject -dates -fingerprint -sha256   # check what you got
```

Sui client si installa sempre e solo il **certificato CA**, mai una chiave
privata. Se la CA è intermedia, installa invece la sua radice (o anche quella).

## Sistemi operativi

### Debian / Ubuntu

```sh
sudo cp minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt   # must end in .crt, PEM content
sudo update-ca-certificates
```

Così la CA viene aggiunta a `/etc/ssl/certs/ca-certificates.crt`, usato da curl, wget,
Python, Go, Node (con `NODE_EXTRA_CA_CERTS` o `--use-openssl-ca`), apt e
dalla maggior parte degli altri programmi del sistema. `/usr/local/share/ca-certificates/`
è il posto giusto per le aggiunte locali; `/usr/share/ca-certificates/` appartiene
ai pacchetti della distribuzione.

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

(Esegui prima `apk add ca-certificates` se `update-ca-certificates` manca.)

### Arch Linux

```sh
sudo trust anchor --store minica-ca.pem
```

### macOS

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain minica-ca.pem
```

Oppure fai doppio clic sul file, aggiungilo al portachiavi *Sistema* in Accesso Portachiavi,
aprilo e imposta *Quando si usa questo certificato* su *Considera sempre attendibile*. Safari e
Chrome usano il portachiavi; Firefox richiede il passaggio aggiuntivo descritto sotto.

### Windows

Come amministratore (PowerShell):

```powershell
Import-Certificate -FilePath .\minica-ca.pem -CertStoreLocation Cert:\LocalMachine\Root
```

oppure `certutil -addstore -f Root minica-ca.pem`, oppure doppio clic → *Installa
certificato* → *Computer locale* → *Metti tutti i certificati nel seguente
archivio* → *Autorità di certificazione radice attendibili*. Edge, Chrome e
.NET/PowerShell usano questo archivio; Firefox richiede il passaggio aggiuntivo descritto sotto.

### Android

Android installa solo file DER o PEM con estensione `.crt`/`.cer`:

```sh
openssl x509 -in minica-ca.pem -outform DER -out minica-ca.crt
```

Copialo sul telefono, poi *Impostazioni → Sicurezza → Crittografia e credenziali →
Installa un certificato → Certificato CA*. Android 11+ avvisa che il
certificato deve essere installato dalle Impostazioni; è il percorso indicato sopra.
Chrome e la maggior parte delle app lo considerano poi attendibile, ma le app che fissano i certificati (pinning) o includono
un proprio archivio di fiducia (e alcune che usano un proprio stack di rete) no.

### iOS / iPadOS

Apri il file `.pem` sul dispositivo (AirDrop, Mail, File) → *Impostazioni → Profilo
scaricato → Installa*, poi abilitalo in *Impostazioni → Generali → Info →
Impostazioni attendibilità certificati*.

## Browser

Chrome, Edge e Safari usano l'archivio del sistema operativo, quindi i passaggi sopra
bastano. **Firefox** mantiene un archivio proprio, salvo diversa configurazione:

- Preferenze → Privacy e sicurezza → Certificati → *Mostra certificati* →
  *Autorità* → *Importa* → seleziona *Considera attendibile questa CA per identificare siti web*; oppure
- imposta `security.enterprise_roots.enabled` su `true` in `about:config` per far usare
  a Firefox l'archivio di sistema di Windows / macOS; oppure
- su Linux, importa nel database NSS del profilo:
  `certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.mozilla/firefox/<profile>` (`certutil` da `libnss3-tools` / `nss-tools`).

Anche Chromium su Linux ha un archivio NSS per le CA installate dall'utente:
`certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.pki/nssdb`.

## Strumenti da riga di comando e linguaggi

### curl

```sh
curl --cacert minica-ca.pem https://intranet.example.com/
export CURL_CA_BUNDLE=/path/to/minica-ca.pem     # for a shell session
```

Dopo aver installato la CA nell'archivio di sistema (sopra) non serve alcuna opzione.
`CURL_CA_BUNDLE` *sostituisce* il bundle, quindi indicagli un file che contenga
anche le CA pubbliche se servono entrambe (ad es. aggiungi il PEM di MiniCA a una copia
di `/etc/ssl/certs/ca-certificates.crt`).

### wget

```sh
wget --ca-certificate=minica-ca.pem https://intranet.example.com/
echo "ca_certificate = /path/to/minica-ca.pem" >> ~/.wgetrc
```

### Python

`urllib`, `http.client` e il modulo `ssl` usano i percorsi predefiniti di OpenSSL,
cioè l'archivio di sistema, e rispettano `SSL_CERT_FILE` / `SSL_CERT_DIR`. La
libreria `requests` (e tutto ciò che si basa su di essa, incluso `pip`) usa invece il
bundle `certifi`:

```sh
export REQUESTS_CA_BUNDLE=/path/to/minica-ca.pem   # requests; replaces the bundle
export SSL_CERT_FILE=/path/to/minica-ca.pem        # ssl / urllib / httpx
pip config set global.cert /path/to/minica-ca.pem  # pip
```

Per mantenere anche le CA pubbliche, aggiungi il PEM di MiniCA a una copia del
bundle di certifi (`python -m certifi` ne stampa il percorso) e fai puntare le variabili alla
copia. `pip install pip-system-certs` o `truststore` fa invece usare a requests l'archivio
del sistema operativo.

### Java / JVM (Kafka, Elasticsearch, Jenkins, ...)

Il download del truststore della CA è un truststore PKCS#12 pronto all'uso (password
`changeit`, con la CA memorizzata come `trustedCertEntry`):

```sh
curl -fsSLo minica-truststore.p12 https://ca.example.com/minica/download/ca/<ca-id>/truststore
java -Djavax.net.ssl.trustStore=minica-truststore.p12 \
     -Djavax.net.ssl.trustStorePassword=changeit \
     -Djavax.net.ssl.trustStoreType=PKCS12 -jar app.jar
```

Quel truststore contiene *solo* la CA di MiniCA. Per aggiungere invece la CA all'archivio
predefinito del JDK (così le CA pubbliche continuano a funzionare):

```sh
keytool -importcert -trustcacerts -noprompt -alias minica \
  -file minica-ca.pem -cacerts -storepass changeit
```

I client Kafka usano `ssl.truststore.location=minica-truststore.p12`,
`ssl.truststore.password=changeit`, `ssl.truststore.type=PKCS12`.

### Go

Go usa l'archivio di sistema (`crypto/x509` legge `/etc/ssl/certs` su Linux) e
rispetta `SSL_CERT_FILE` / `SSL_CERT_DIR`. Per aggiungere una CA dal codice:

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

Questo *aggiunge* alle CA incluse in Node. `--use-openssl-ca` fa usare invece a Node
l'archivio di sistema.

### yt-dlp

yt-dlp è un programma Python e segue le regole di Python: con `certifi`
installato (il caso più comune) usa il bundle di certifi, altrimenti l'archivio
predefinito di OpenSSL. Installa la CA nell'archivio di sistema ed elimina /
aggira certifi, oppure fai puntare lo stack HTTP di yt-dlp a un bundle che contenga entrambe:

```sh
cat "$(python3 -m certifi)" minica-ca.pem > ~/.config/yt-dlp/ca-bundle.pem
SSL_CERT_FILE=~/.config/yt-dlp/ca-bundle.pem REQUESTS_CA_BUNDLE=~/.config/yt-dlp/ca-bundle.pem yt-dlp https://media.intranet.example.com/...
```

Evita `--no-check-certificates`: disattiva del tutto la verifica.

## Server e servizi

### Nginx

Tre cose diverse si confondono facilmente:

- **Servire un certificato emesso da MiniCA.** Scarica il *Bundle* (zip) del
  certificato — `cert.pem`, `cert.key` e `ca.pem` — e usa
  ```nginx
  ssl_certificate     /etc/nginx/tls/cert.pem;    # or cat cert.pem ca.pem > fullchain.pem
  ssl_certificate_key /etc/nginx/tls/cert.key;
  ```
  I client devono poi avere la CA installata come descritto in questa pagina.
- **Nginx come client TLS** (proxy verso un upstream che presenta un
  certificato MiniCA):
  ```nginx
  proxy_ssl_verify on;
  proxy_ssl_trusted_certificate /etc/nginx/tls/minica-ca.pem;
  proxy_ssl_name upstream.example.com;
  ```
- **Certificati client (mTLS) emessi da MiniCA:**
  ```nginx
  ssl_client_certificate /etc/nginx/tls/minica-ca.pem;
  ssl_verify_client on;
  ssl_crl /etc/nginx/tls/minica.crl.pem;   # optional: openssl crl -inform DER -in <crl> -out minica.crl.pem
  ```
  La CRL si trova in `https://ca.example.com/minica/crl/<ca-id>` (DER).

### Docker

Per un' **immagine**, aggiungi la CA in fase di build in modo che ogni strumento dell'immagine la veda:

```dockerfile
# Debian/Ubuntu based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN update-ca-certificates
# Alpine based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN apk add --no-cache ca-certificates && update-ca-certificates
```

Per un **container che non puoi ricostruire**, monta sopra il bundle dell'immagine un bundle che contenga già
la CA (ad es. il `/etc/ssl/certs/ca-certificates.crt` dell'host dopo aver installato
la CA sull'host), oppure fai puntare gli strumenti al suo interno
tramite le variabili d'ambiente indicate sopra:

```yaml
    environment:
      SSL_CERT_FILE:        /etc/ssl/certs/ca-certificates.crt   # OpenSSL, Python ssl, Go, Ruby
      REQUESTS_CA_BUNDLE:   /etc/ssl/certs/ca-certificates.crt   # Python requests
      CURL_CA_BUNDLE:       /etc/ssl/certs/ca-certificates.crt   # curl
      NODE_EXTRA_CA_CERTS:  /etc/ssl/certs/ca-certificates.crt   # Node.js
    volumes:
      - /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro
```

Le immagini basate su distribuzioni che tengono il bundle altrove
(famiglia RHEL: `/etc/pki/tls/certs/ca-bundle.crt`) richiedono invece quel percorso.

Il *daemon* di Docker considera attendibile la CA di un registry privato da
`/etc/docker/certs.d/<registry:port>/ca.crt`, indipendentemente dall'archivio di sistema.

### LLDAP

LLDAP è un server: dagli un certificato emesso da MiniCA per il suo listener
LDAPS (scarica il bundle del certificato; la chiave è `cert.key`):

```toml
# lldap_config.toml
[ldaps_options]
enabled = true
port = 6360
cert_file = "/data/tls/cert.pem"
key_file = "/data/tls/cert.key"
```

oppure `LLDAP_LDAPS_OPTIONS__ENABLED=true`, `LLDAP_LDAPS_OPTIONS__CERT_FILE=...`,
`LLDAP_LDAPS_OPTIONS__KEY_FILE=...` nell'ambiente. Ogni client LDAP
(Authelia, Nextcloud, Jellyfin, ...) deve poi avere la CA di MiniCA nel proprio
archivio di fiducia, secondo le procedure sopra per la piattaforma o il linguaggio su cui gira.

## Pubblicare MiniCA tramite Nginx

Con il login di MiniCA basta un solo prefisso. MiniCA protegge da sé le proprie pagine private e questa guida resta pubblica in `/minica/how-to-use`:

```nginx
location /minica/ {
    proxy_pass http://minica:9988;
    include /etc/nginx/snippets/proxy.conf;
}
```

Con SSO (Authelia, oauth2-proxy, ...) il prefisso è protetto, quindi le pagine pubbliche richiedono una regola a parte. Mantieni vuoti gli header di identità in quella regola, perché MiniCA si fida di essi quando provengono dal proxy:

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

## Verificare che funzioni

```sh
openssl s_client -connect intranet.example.com:443 -servername intranet.example.com </dev/null 2>/dev/null | grep "Verify return code"
curl -v https://intranet.example.com/ 2>&1 | grep -E "SSL certificate verify|issuer"
```

`Verify return code: 0 (ok)` significa che il client ha trovato e considerato attendibile la CA.
