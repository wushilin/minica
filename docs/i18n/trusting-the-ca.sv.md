<!-- source-sha256: 51e546526752332fcfc280e7dff9c74d662f180be9dc12f325b1f7754935dbb2 -->
# Lita på en MiniCA-certifikatutfärdare

Certifikat utfärdade av MiniCA accepteras av en klient först när klienten
litar på den utfärdande CA:n. Den här sidan samlar recepten för de vanligaste
plattformarna och verktygen. Allt utgår från de två offentliga nedladdningar
som varje CA har (ingen inloggning behövs):

| Nedladdning | URL | Använd för |
| --- | --- | --- |
| CA-certifikat (PEM) | `https://ca.example.com/minica/<ca-id>/download` | allt utom Java |
| CA-truststore (PKCS#12, lösenord `changeit`) | `https://ca.example.com/minica/download/ca/<ca-id>/truststore` | Java / JVM-applikationer |

Båda är också länkade från det offentliga CA-indexet på `https://ca.example.com/minica/`
och från CA-sidan. Filen är uppkallad efter CA:ns common name, t.ex.
`Homelab_CA.pem`; exemplen nedan kallar den `minica-ca.pem` / `minica-ca.crt`.

```sh
curl -fsSLo minica-ca.pem https://ca.example.com/minica/<ca-id>/download
openssl x509 -in minica-ca.pem -noout -subject -dates -fingerprint -sha256   # check what you got
```

Det är bara **CA-certifikatet** som någonsin installeras på klienter — aldrig en privat
nyckel. Om CA:n är en mellanliggande CA, installera dess rot i stället (eller också).

## Operativsystem

### Debian / Ubuntu

```sh
sudo cp minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt   # must end in .crt, PEM content
sudo update-ca-certificates
```

Detta lägger till CA:n i `/etc/ssl/certs/ca-certificates.crt`, som curl, wget,
Python, Go, Node (med `NODE_EXTRA_CA_CERTS` eller `--use-openssl-ca`), apt och
de flesta andra program på systemet använder. `/usr/local/share/ca-certificates/`
är rätt plats för lokala tillägg; `/usr/share/ca-certificates/` tillhör
distributionens paket.

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

(`apk add ca-certificates` först om `update-ca-certificates` saknas.)

### Arch Linux

```sh
sudo trust anchor --store minica-ca.pem
```

### macOS

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain minica-ca.pem
```

Eller dubbelklicka på filen, lägg till den i nyckelringen *System* i Nyckelhanteraren (Keychain Access),
öppna den och sätt *När detta certifikat används* till *Lita alltid på*. Safari och
Chrome använder nyckelringen; Firefox behöver det extra steget nedan.

### Windows

Som administratör (PowerShell):

```powershell
Import-Certificate -FilePath .\minica-ca.pem -CertStoreLocation Cert:\LocalMachine\Root
```

eller `certutil -addstore -f Root minica-ca.pem`, eller dubbelklicka → *Installera
certifikat* → *Lokal dator* → *Placera alla certifikat i följande
arkiv* → *Betrodda rotcertifikatutfärdare*. Edge, Chrome och
.NET/PowerShell använder det här arkivet; Firefox behöver det extra steget nedan.

### Android

Android installerar bara DER- eller PEM-filer med namn som slutar på `.crt`/`.cer`:

```sh
openssl x509 -in minica-ca.pem -outform DER -out minica-ca.crt
```

Kopiera den till telefonen och välj sedan *Inställningar → Säkerhet → Kryptering och inloggningsuppgifter →
Installera ett certifikat → CA-certifikat*. Android 11+ varnar för att
certifikatet måste installeras från Inställningar; det är vägen ovan.
Chrome och de flesta appar litar sedan på det, men appar som fäster certifikat (pinning) eller levererar
sitt eget förtroendearkiv (och vissa som använder sin egen nätverksstack) gör det inte.

### iOS / iPadOS

Öppna `.pem`-filen på enheten (AirDrop, Mail, Filer) → *Inställningar → Profil
hämtad → Installera*, och aktivera den sedan under *Inställningar → Allmänt → Om →
Certifikatförtroende*.

## Webbläsare

Chrome, Edge och Safari använder operativsystemets arkiv, så stegen ovan
räcker. **Firefox** har ett eget arkiv om inget annat anges:

- Inställningar → Integritet och säkerhet → Certifikat → *Visa certifikat* →
  *Utfärdare* → *Importera* → bocka i *Lita på denna CA för att identifiera webbplatser*; eller
- sätt `security.enterprise_roots.enabled` till `true` i `about:config` så att
  Firefox använder systemarkivet i Windows / macOS; eller
- på Linux, importera till profilens NSS-databas:
  `certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.mozilla/firefox/<profile>` (`certutil` från `libnss3-tools` / `nss-tools`).

Chromium på Linux har också ett NSS-arkiv för användarinstallerade CA:er:
`certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.pki/nssdb`.

## Kommandoradsverktyg och språk

### curl

```sh
curl --cacert minica-ca.pem https://intranet.example.com/
export CURL_CA_BUNDLE=/path/to/minica-ca.pem     # for a shell session
```

Efter att CA:n installerats i systemarkivet (ovan) behövs ingen flagga.
`CURL_CA_BUNDLE` *ersätter* paketet, så peka den på en fil som också
innehåller de publika CA:erna om du behöver båda (t.ex. lägg till MiniCA-PEM i en kopia
av `/etc/ssl/certs/ca-certificates.crt`).

### wget

```sh
wget --ca-certificate=minica-ca.pem https://intranet.example.com/
echo "ca_certificate = /path/to/minica-ca.pem" >> ~/.wgetrc
```

### Python

`urllib`, `http.client` och modulen `ssl` använder OpenSSL:s standardsökvägar,
dvs. systemarkivet, och respekterar `SSL_CERT_FILE` / `SSL_CERT_DIR`. Biblioteket
`requests` (och allt som bygger på det, inklusive `pip`) använder i stället
paketet från `certifi`:

```sh
export REQUESTS_CA_BUNDLE=/path/to/minica-ca.pem   # requests; replaces the bundle
export SSL_CERT_FILE=/path/to/minica-ca.pem        # ssl / urllib / httpx
pip config set global.cert /path/to/minica-ca.pem  # pip
```

För att behålla de publika CA:erna också, lägg till MiniCA-PEM i en kopia av certifis
paket (`python -m certifi` skriver ut dess sökväg) och peka variablerna på
kopian. `pip install pip-system-certs` eller `truststore` får requests att använda
operativsystemets arkiv i stället.

### Java / JVM (Kafka, Elasticsearch, Jenkins, ...)

Nedladdningen av CA-truststore är en färdig PKCS#12-truststore (lösenord
`changeit`, med CA:n lagrad som en `trustedCertEntry`):

```sh
curl -fsSLo minica-truststore.p12 https://ca.example.com/minica/download/ca/<ca-id>/truststore
java -Djavax.net.ssl.trustStore=minica-truststore.p12 \
     -Djavax.net.ssl.trustStorePassword=changeit \
     -Djavax.net.ssl.trustStoreType=PKCS12 -jar app.jar
```

Den truststoren innehåller *bara* MiniCA:s CA. Så här lägger du i stället till CA:n i JDK:ns
standardarkiv (så att publika CA:er fortsätter fungera):

```sh
keytool -importcert -trustcacerts -noprompt -alias minica \
  -file minica-ca.pem -cacerts -storepass changeit
```

Kafka-klienter använder `ssl.truststore.location=minica-truststore.p12`,
`ssl.truststore.password=changeit`, `ssl.truststore.type=PKCS12`.

### Go

Go använder systemarkivet (`crypto/x509` läser `/etc/ssl/certs` på Linux) och
respekterar `SSL_CERT_FILE` / `SSL_CERT_DIR`. Så här lägger du till en CA från kod:

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

Detta *lägger till* i Nodes medföljande CA:er. `--use-openssl-ca` får Node att använda
systemarkivet i stället.

### yt-dlp

yt-dlp är ett Python-program och följer Pythons regler: om `certifi` är
installerat (det vanliga fallet) används certifis paket, annars OpenSSL:s
standardarkiv. Antingen installerar du CA:n i systemarkivet och tar bort /
kringgår certifi, eller så pekar du yt-dlp:s HTTP-stack på ett paket som innehåller båda:

```sh
cat "$(python3 -m certifi)" minica-ca.pem > ~/.config/yt-dlp/ca-bundle.pem
SSL_CERT_FILE=~/.config/yt-dlp/ca-bundle.pem REQUESTS_CA_BUNDLE=~/.config/yt-dlp/ca-bundle.pem yt-dlp https://media.intranet.example.com/...
```

Undvik `--no-check-certificates`; det stänger av verifieringen helt.

## Servrar och tjänster

### Nginx

Tre olika saker är lätta att blanda ihop:

- **Servera ett MiniCA-utfärdat certifikat.** Ladda ned certifikatets
  *Bundle* (zip) — `cert.pem`, `cert.key` och `ca.pem` — och använd
  ```nginx
  ssl_certificate     /etc/nginx/tls/cert.pem;    # or cat cert.pem ca.pem > fullchain.pem
  ssl_certificate_key /etc/nginx/tls/cert.key;
  ```
  Klienter behöver då CA:n installerad enligt beskrivningen på den här sidan.
- **Nginx som TLS-klient** (proxy till en uppströmsserver som presenterar ett
  MiniCA-certifikat):
  ```nginx
  proxy_ssl_verify on;
  proxy_ssl_trusted_certificate /etc/nginx/tls/minica-ca.pem;
  proxy_ssl_name upstream.example.com;
  ```
- **Klientcertifikat (mTLS) utfärdade av MiniCA:**
  ```nginx
  ssl_client_certificate /etc/nginx/tls/minica-ca.pem;
  ssl_verify_client on;
  ssl_crl /etc/nginx/tls/minica.crl.pem;   # optional: openssl crl -inform DER -in <crl> -out minica.crl.pem
  ```
  CRL:en finns på `https://ca.example.com/minica/crl/<ca-id>` (DER).

### Docker

För en **image**, lägg till CA:n vid bygget så att alla verktyg i imagen ser den:

```dockerfile
# Debian/Ubuntu based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN update-ca-certificates
# Alpine based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN apk add --no-cache ca-certificates && update-ca-certificates
```

För en **container som du inte kan bygga om**, montera ett paket som redan innehåller
CA:n (t.ex. värdens `/etc/ssl/certs/ca-certificates.crt` efter att ha installerat
CA:n på värden) över imagens paket, eller peka verktygen inuti på det
via miljövariablerna ovan:

```yaml
    environment:
      SSL_CERT_FILE:        /etc/ssl/certs/ca-certificates.crt   # OpenSSL, Python ssl, Go, Ruby
      REQUESTS_CA_BUNDLE:   /etc/ssl/certs/ca-certificates.crt   # Python requests
      CURL_CA_BUNDLE:       /etc/ssl/certs/ca-certificates.crt   # curl
      NODE_EXTRA_CA_CERTS:  /etc/ssl/certs/ca-certificates.crt   # Node.js
    volumes:
      - /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro
```

Images baserade på distributioner som har paketet på annan plats
(RHEL-familjen: `/etc/pki/tls/certs/ca-bundle.crt`) behöver den sökvägen i stället.

Docker-*daemonen* litar på ett privat registers CA från
`/etc/docker/certs.d/<registry:port>/ca.crt`, oberoende av systemarkivet.

### LLDAP

LLDAP är en server: ge den ett certifikat utfärdat av MiniCA för sin LDAPS-lyssnare
(ladda ned certifikatets bundle; nyckeln är `cert.key`):

```toml
# lldap_config.toml
[ldaps_options]
enabled = true
port = 6360
cert_file = "/data/tls/cert.pem"
key_file = "/data/tls/cert.key"
```

eller `LLDAP_LDAPS_OPTIONS__ENABLED=true`, `LLDAP_LDAPS_OPTIONS__CERT_FILE=...`,
`LLDAP_LDAPS_OPTIONS__KEY_FILE=...` i miljön. Varje LDAP-klient
(Authelia, Nextcloud, Jellyfin, ...) behöver sedan MiniCA:s CA i sitt eget
förtroendearkiv, enligt recepten ovan för den plattform eller det språk den körs på.

## Publicera MiniCA via Nginx

Med MiniCA:s egen inloggning räcker ett prefix. MiniCA skyddar sina privata sidor själv, och den här guiden förblir offentlig på `/minica/how-to-use`:

```nginx
location /minica/ {
    proxy_pass http://minica:9988;
    include /etc/nginx/snippets/proxy.conf;
}
```

Med SSO (Authelia, oauth2-proxy, ...) skyddas prefixet, så de offentliga sidorna behöver en egen regel. Håll identitetsrubrikerna rensade i den regeln, eftersom MiniCA litar på dem när de kommer från proxyn:

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

## Kontrollera att det fungerar

```sh
openssl s_client -connect intranet.example.com:443 -servername intranet.example.com </dev/null 2>/dev/null | grep "Verify return code"
curl -v https://intranet.example.com/ 2>&1 | grep -E "SSL certificate verify|issuer"
```

`Verify return code: 0 (ok)` betyder att klienten hittade och litade på CA:n.
