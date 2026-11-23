<!-- source-sha256: 51e546526752332fcfc280e7dff9c74d662f180be9dc12f325b1f7754935dbb2 -->
# Sådan stoler du på en MiniCA-certifikatudsteder

Certifikater udstedt af MiniCA accepteres kun af en klient, når klienten
stoler på den udstedende CA. Denne side samler opskrifterne til de gængse
platforme og værktøjer. Alt tager udgangspunkt i de to offentlige downloads,
som enhver CA har (ingen login nødvendigt):

| Download | URL | Bruges til |
| --- | --- | --- |
| CA-certifikat (PEM) | `https://ca.example.com/minica/<ca-id>/download` | alt undtagen Java |
| CA-truststore (PKCS#12, adgangskode `changeit`) | `https://ca.example.com/minica/download/ca/<ca-id>/truststore` | Java / JVM-applikationer |

Begge er også linket fra det offentlige CA-indeks på `https://ca.example.com/minica/`
og fra CA-siden. Filen er opkaldt efter CA'ens common name, f.eks.
`Homelab_CA.pem`; eksemplerne nedenfor kalder den `minica-ca.pem` / `minica-ca.crt`.

```sh
curl -fsSLo minica-ca.pem https://ca.example.com/minica/<ca-id>/download
openssl x509 -in minica-ca.pem -noout -subject -dates -fingerprint -sha256   # check what you got
```

Det er kun **CA-certifikatet**, der nogensinde installeres på klienter — aldrig en privat
nøgle. Hvis CA'en er en mellemliggende CA, så installér i stedet (eller også) dens rod.

## Operativsystemer

### Debian / Ubuntu

```sh
sudo cp minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt   # must end in .crt, PEM content
sudo update-ca-certificates
```

Det tilføjer CA'en til `/etc/ssl/certs/ca-certificates.crt`, som curl, wget,
Python, Go, Node (med `NODE_EXTRA_CA_CERTS` eller `--use-openssl-ca`), apt og
de fleste andre programmer på systemet bruger. `/usr/local/share/ca-certificates/`
er det rette sted til lokale tilføjelser; `/usr/share/ca-certificates/` tilhører
distributionens pakke.

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

(Kør først `apk add ca-certificates`, hvis `update-ca-certificates` mangler.)

### Arch Linux

```sh
sudo trust anchor --store minica-ca.pem
```

### macOS

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain minica-ca.pem
```

Eller dobbeltklik på filen, føj den til nøglringen *System* i Nøglering
(Keychain Access), åbn den og sæt *Ved brug af dette certifikat* til *Stol altid på*.
Safari og Chrome bruger nøglringen; Firefox kræver det ekstra trin nedenfor.

### Windows

Som administrator (PowerShell):

```powershell
Import-Certificate -FilePath .\minica-ca.pem -CertStoreLocation Cert:\LocalMachine\Root
```

eller `certutil -addstore -f Root minica-ca.pem`, eller dobbeltklik → *Installer
certifikat* → *Lokal computer* → *Placer alle certifikater i følgende
lager* → *Pålidelige rodcertificeringsmyndigheder*. Edge, Chrome og
.NET/PowerShell bruger dette lager; Firefox kræver det ekstra trin nedenfor.

### Android

Android installerer kun DER- eller PEM-filer med et `.crt`/`.cer`-navn:

```sh
openssl x509 -in minica-ca.pem -outform DER -out minica-ca.crt
```

Kopiér filen til telefonen, og gå derefter til *Indstillinger → Sikkerhed → Kryptering og legitimationsoplysninger →
Installér et certifikat → CA-certifikat*. Android 11+ advarer om, at
certifikatet skal installeres fra Indstillinger; det er stien ovenfor.
Chrome og de fleste apps stoler derefter på det, men apps, der pinner certifikater eller leverer
deres eget trust store (og nogle, der bruger deres egen netværksstak), gør det ikke.

### iOS / iPadOS

Åbn `.pem`-filen på enheden (AirDrop, Mail, Filer) → *Indstillinger → Profil
hentet → Installér*, og aktivér den derefter under *Indstillinger → Generelt → Om →
Certifikattillid*.

## Browsere

Chrome, Edge og Safari bruger operativsystemets lager, så trinnene ovenfor
er nok. **Firefox** har sit eget lager, medmindre andet er angivet:

- Indstillinger → Anonymitet og sikkerhed → Certifikater → *Vis certifikater* →
  *Myndigheder* → *Importér* → sæt hak ved *Stol på denne CA til at identificere websteder*; eller
- sæt `security.enterprise_roots.enabled` til `true` i `about:config`, så
  Firefox bruger systemlageret i Windows / macOS; eller
- på Linux: importér i profilens NSS-database:
  `certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.mozilla/firefox/<profile>` (`certutil` fra `libnss3-tools` / `nss-tools`).

Chromium på Linux har også et NSS-lager til brugerinstallerede CA'er:
`certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.pki/nssdb`.

## Kommandolinjeværktøjer og sprog

### curl

```sh
curl --cacert minica-ca.pem https://intranet.example.com/
export CURL_CA_BUNDLE=/path/to/minica-ca.pem     # for a shell session
```

Når CA'en er installeret i systemlageret (ovenfor), er ingen indstilling nødvendig.
`CURL_CA_BUNDLE` *erstatter* bundlen, så peg den på en fil, der også
indeholder de offentlige CA'er, hvis du har brug for begge (f.eks. tilføj MiniCA-PEM til en kopi
af `/etc/ssl/certs/ca-certificates.crt`).

### wget

```sh
wget --ca-certificate=minica-ca.pem https://intranet.example.com/
echo "ca_certificate = /path/to/minica-ca.pem" >> ~/.wgetrc
```

### Python

`urllib`, `http.client` og modulet `ssl` bruger OpenSSL's standardstier,
dvs. systemlageret, og respekterer `SSL_CERT_FILE` / `SSL_CERT_DIR`. Biblioteket
`requests` (og alt, der er bygget på det, herunder `pip`) bruger i stedet
`certifi`-bundlen:

```sh
export REQUESTS_CA_BUNDLE=/path/to/minica-ca.pem   # requests; replaces the bundle
export SSL_CERT_FILE=/path/to/minica-ca.pem        # ssl / urllib / httpx
pip config set global.cert /path/to/minica-ca.pem  # pip
```

For også at beholde de offentlige CA'er skal du tilføje MiniCA-PEM til en kopi af certifis
bundle (`python -m certifi` udskriver stien) og pege variablerne på
kopien. `pip install pip-system-certs` eller `truststore` får requests til at bruge
operativsystemets lager i stedet.

### Java / JVM (Kafka, Elasticsearch, Jenkins, ...)

CA-truststore-downloaden er en brugsklar PKCS#12-truststore (adgangskode
`changeit`, CA'en gemt som en `trustedCertEntry`):

```sh
curl -fsSLo minica-truststore.p12 https://ca.example.com/minica/download/ca/<ca-id>/truststore
java -Djavax.net.ssl.trustStore=minica-truststore.p12 \
     -Djavax.net.ssl.trustStorePassword=changeit \
     -Djavax.net.ssl.trustStoreType=PKCS12 -jar app.jar
```

Den truststore indeholder *kun* MiniCA-CA'en. Sådan føjer du i stedet CA'en til JDK'ets
standardlager (så offentlige CA'er stadig virker):

```sh
keytool -importcert -trustcacerts -noprompt -alias minica \
  -file minica-ca.pem -cacerts -storepass changeit
```

Kafka-klienter bruger `ssl.truststore.location=minica-truststore.p12`,
`ssl.truststore.password=changeit`, `ssl.truststore.type=PKCS12`.

### Go

Go bruger systemlageret (`crypto/x509` læser `/etc/ssl/certs` på Linux) og
respekterer `SSL_CERT_FILE` / `SSL_CERT_DIR`. Sådan tilføjer du en CA fra kode:

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

Det *tilføjer* til Nodes medfølgende CA'er. `--use-openssl-ca` får Node til at bruge
systemlageret i stedet.

### yt-dlp

yt-dlp er et Python-program og følger Python-reglerne: hvis `certifi` er
installeret (det almindelige tilfælde), bruger det certifis bundle, ellers OpenSSL's
standardlager. Enten installér CA'en i systemlageret og fjern /
omgå certifi, eller peg yt-dlp's HTTP-stak på en bundle, der indeholder begge:

```sh
cat "$(python3 -m certifi)" minica-ca.pem > ~/.config/yt-dlp/ca-bundle.pem
SSL_CERT_FILE=~/.config/yt-dlp/ca-bundle.pem REQUESTS_CA_BUNDLE=~/.config/yt-dlp/ca-bundle.pem yt-dlp https://media.intranet.example.com/...
```

Undgå `--no-check-certificates`; den slår verificeringen helt fra.

## Servere og tjenester

### Nginx

Tre forskellige ting er lette at forveksle:

- **Servering af et MiniCA-udstedt certifikat.** Download certifikatets
  *Bundle* (zip) — `cert.pem`, `cert.key` og `ca.pem` — og brug
  ```nginx
  ssl_certificate     /etc/nginx/tls/cert.pem;    # or cat cert.pem ca.pem > fullchain.pem
  ssl_certificate_key /etc/nginx/tls/cert.key;
  ```
  Klienter skal derefter have CA'en installeret som beskrevet på denne side.
- **Nginx som TLS-klient** (proxy til en upstream, der præsenterer et
  MiniCA-certifikat):
  ```nginx
  proxy_ssl_verify on;
  proxy_ssl_trusted_certificate /etc/nginx/tls/minica-ca.pem;
  proxy_ssl_name upstream.example.com;
  ```
- **Klientcertifikater (mTLS) udstedt af MiniCA:**
  ```nginx
  ssl_client_certificate /etc/nginx/tls/minica-ca.pem;
  ssl_verify_client on;
  ssl_crl /etc/nginx/tls/minica.crl.pem;   # optional: openssl crl -inform DER -in <crl> -out minica.crl.pem
  ```
  CRL'en findes på `https://ca.example.com/minica/crl/<ca-id>` (DER).

### Docker

For et **image** skal du tilføje CA'en ved build, så alle værktøjer i imaget ser den:

```dockerfile
# Debian/Ubuntu based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN update-ca-certificates
# Alpine based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN apk add --no-cache ca-certificates && update-ca-certificates
```

For en **container, du ikke kan genbygge**, skal du mounte en bundle, der allerede indeholder
CA'en (f.eks. værtens `/etc/ssl/certs/ca-certificates.crt` efter installation af
CA'en på værten) over imagets bundle, eller pege værktøjerne indeni på den
via miljøvariablerne ovenfor:

```yaml
    environment:
      SSL_CERT_FILE:        /etc/ssl/certs/ca-certificates.crt   # OpenSSL, Python ssl, Go, Ruby
      REQUESTS_CA_BUNDLE:   /etc/ssl/certs/ca-certificates.crt   # Python requests
      CURL_CA_BUNDLE:       /etc/ssl/certs/ca-certificates.crt   # curl
      NODE_EXTRA_CA_CERTS:  /etc/ssl/certs/ca-certificates.crt   # Node.js
    volumes:
      - /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro
```

Images baseret på distributioner, der opbevarer bundlen et andet sted
(RHEL-familien: `/etc/pki/tls/certs/ca-bundle.crt`), skal bruge den sti i stedet.

Docker-*daemonen* stoler på et privat registers CA fra
`/etc/docker/certs.d/<registry:port>/ca.crt`, uafhængigt af systemlageret.

### LLDAP

LLDAP er en server: giv den et certifikat udstedt af MiniCA til dens LDAPS-
lytter (download certifikatets bundle; nøglen er `cert.key`):

```toml
# lldap_config.toml
[ldaps_options]
enabled = true
port = 6360
cert_file = "/data/tls/cert.pem"
key_file = "/data/tls/cert.key"
```

eller `LLDAP_LDAPS_OPTIONS__ENABLED=true`, `LLDAP_LDAPS_OPTIONS__CERT_FILE=...`,
`LLDAP_LDAPS_OPTIONS__KEY_FILE=...` i miljøet. Hver LDAP-klient
(Authelia, Nextcloud, Jellyfin, ...) skal derefter have MiniCA-CA'en i sit eget
trust store, efter opskrifterne ovenfor for den platform eller det sprog, den kører på.

## Udgivelse af MiniCA via Nginx

Med MiniCA's eget login er ét præfiks nok. MiniCA beskytter selv sine private sider, og denne vejledning forbliver offentlig på `/minica/how-to-use`:

```nginx
location /minica/ {
    proxy_pass http://minica:9988;
    include /etc/nginx/snippets/proxy.conf;
}
```

Med SSO (Authelia, oauth2-proxy, ...) er præfikset beskyttet, så de offentlige sider kræver en egen regel. Hold identitetsheaderne tømt i den regel, fordi MiniCA stoler på dem, når de kommer fra proxyen:

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

## Kontrol af, at det virker

```sh
openssl s_client -connect intranet.example.com:443 -servername intranet.example.com </dev/null 2>/dev/null | grep "Verify return code"
curl -v https://intranet.example.com/ 2>&1 | grep -E "SSL certificate verify|issuer"
```

`Verify return code: 0 (ok)` betyder, at klienten fandt og stolede på CA'en.
