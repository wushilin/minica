<!-- source-sha256: 51e546526752332fcfc280e7dff9c74d662f180be9dc12f325b1f7754935dbb2 -->
# Cum să te încrezi într-o autoritate de certificare MiniCA

Certificatele emise de MiniCA sunt acceptate de un client abia după ce acel
client se încrede în CA-ul emitent. Această pagină reunește rețetele pentru
platformele și instrumentele uzuale. Totul pornește de la cele două
descărcări publice pe care le are fiecare CA (fără autentificare):

| Descărcare | URL | Pentru ce se folosește |
| --- | --- | --- |
| Certificatul CA (PEM) | `https://ca.example.com/minica/<ca-id>/download` | orice, cu excepția Java |
| Truststore-ul CA (PKCS#12, parola `changeit`) | `https://ca.example.com/minica/download/ca/<ca-id>/truststore` | aplicații Java / JVM |

Ambele sunt legate și din indexul public al CA-urilor, la `https://ca.example.com/minica/`,
și din pagina CA-ului. Fișierul poartă numele comun (common name) al CA-ului, de ex.
`Homelab_CA.pem`; exemplele de mai jos îl numesc `minica-ca.pem` / `minica-ca.crt`.

```sh
curl -fsSLo minica-ca.pem https://ca.example.com/minica/<ca-id>/download
openssl x509 -in minica-ca.pem -noout -subject -dates -fingerprint -sha256   # check what you got
```

Pe clienți se instalează întotdeauna doar **certificatul CA** — niciodată o cheie
privată. Dacă CA-ul este intermediar, instalați în schimb rădăcina lui (sau și pe aceasta).

## Sisteme de operare

### Debian / Ubuntu

```sh
sudo cp minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt   # must end in .crt, PEM content
sudo update-ca-certificates
```

Aceasta adaugă CA-ul în `/etc/ssl/certs/ca-certificates.crt`, folosit de curl, wget,
Python, Go, Node (cu `NODE_EXTRA_CA_CERTS` sau `--use-openssl-ca`), apt și
majoritatea celorlalte programe din sistem. `/usr/local/share/ca-certificates/`
este locul potrivit pentru adăugările locale; `/usr/share/ca-certificates/` aparține
pachetului distribuției.

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

(Rulați mai întâi `apk add ca-certificates` dacă `update-ca-certificates` lipsește.)

### Arch Linux

```sh
sudo trust anchor --store minica-ca.pem
```

### macOS

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain minica-ca.pem
```

Sau faceți dublu clic pe fișier, adăugați-l în keychain-ul *System* din Keychain Access,
deschideți-l și setați *When using this certificate* la *Always Trust*. Safari și
Chrome folosesc keychain-ul; Firefox are nevoie de pasul suplimentar de mai jos.

### Windows

Ca administrator (PowerShell):

```powershell
Import-Certificate -FilePath .\minica-ca.pem -CertStoreLocation Cert:\LocalMachine\Root
```

sau `certutil -addstore -f Root minica-ca.pem`, sau dublu clic → *Install
Certificate* → *Local Machine* → *Place all certificates in the following
store* → *Trusted Root Certification Authorities*. Edge, Chrome și
.NET/PowerShell folosesc acest store; Firefox are nevoie de pasul suplimentar de mai jos.

### Android

Android instalează doar fișiere DER sau PEM cu nume terminat în `.crt`/`.cer`:

```sh
openssl x509 -in minica-ca.pem -outform DER -out minica-ca.crt
```

Copiați-l pe telefon, apoi *Settings → Security → Encryption & credentials →
Install a certificate → CA certificate*. Android 11+ avertizează că
certificatul trebuie instalat din Setări; aceasta este calea de mai sus.
Chrome și majoritatea aplicațiilor îl vor considera apoi de încredere, dar aplicațiile care fixează (pin) certificatele sau includ
propriul trust store (și unele care folosesc propriul stack de rețea) nu o vor face.

### iOS / iPadOS

Deschideți fișierul `.pem` pe dispozitiv (AirDrop, Mail, Files) → *Settings → Profile
Downloaded → Install*, apoi activați-l la *Settings → General → About →
Certificate Trust Settings*.

## Browsere

Chrome, Edge și Safari folosesc store-ul sistemului de operare, deci pașii de mai sus
sunt suficienți. **Firefox** își păstrează propriul store, dacă nu i se spune altfel:

- Preferences → Privacy & Security → Certificates → *View Certificates* →
  *Authorities* → *Import* → bifați *Trust this CA to identify websites*; sau
- setați `security.enterprise_roots.enabled` la `true` în `about:config` pentru ca
  Firefox să folosească store-ul de sistem Windows / macOS; sau
- pe Linux, importați în baza de date NSS a profilului:
  `certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.mozilla/firefox/<profile>` (`certutil` din `libnss3-tools` / `nss-tools`).

Chromium pe Linux are, de asemenea, un store NSS pentru CA-urile instalate de utilizator:
`certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.pki/nssdb`.

## Instrumente în linia de comandă și limbaje

### curl

```sh
curl --cacert minica-ca.pem https://intranet.example.com/
export CURL_CA_BUNDLE=/path/to/minica-ca.pem     # for a shell session
```

După instalarea CA-ului în store-ul sistemului (mai sus) nu mai este necesară nicio opțiune.
`CURL_CA_BUNDLE` *înlocuiește* bundle-ul, deci îndreptați-l spre un fișier care conține
și CA-urile publice, dacă aveți nevoie de ambele (de ex. adăugați PEM-ul MiniCA la o copie
a fișierului `/etc/ssl/certs/ca-certificates.crt`).

### wget

```sh
wget --ca-certificate=minica-ca.pem https://intranet.example.com/
echo "ca_certificate = /path/to/minica-ca.pem" >> ~/.wgetrc
```

### Python

`urllib`, `http.client` și modulul `ssl` folosesc căile implicite OpenSSL,
adică store-ul sistemului, și respectă `SSL_CERT_FILE` / `SSL_CERT_DIR`. Biblioteca
`requests` (și tot ce se bazează pe ea, inclusiv `pip`) folosește în schimb
bundle-ul `certifi`:

```sh
export REQUESTS_CA_BUNDLE=/path/to/minica-ca.pem   # requests; replaces the bundle
export SSL_CERT_FILE=/path/to/minica-ca.pem        # ssl / urllib / httpx
pip config set global.cert /path/to/minica-ca.pem  # pip
```

Pentru a păstra și CA-urile publice, adăugați PEM-ul MiniCA la o copie a bundle-ului
certifi (`python -m certifi` afișează calea lui) și îndreptați variabilele spre
copie. `pip install pip-system-certs` sau `truststore` face ca requests să folosească
în schimb store-ul sistemului de operare.

### Java / JVM (Kafka, Elasticsearch, Jenkins, ...)

Truststore-ul CA descărcat este un truststore PKCS#12 gata de utilizare (parola
`changeit`, CA-ul stocat ca `trustedCertEntry`):

```sh
curl -fsSLo minica-truststore.p12 https://ca.example.com/minica/download/ca/<ca-id>/truststore
java -Djavax.net.ssl.trustStore=minica-truststore.p12 \
     -Djavax.net.ssl.trustStorePassword=changeit \
     -Djavax.net.ssl.trustStoreType=PKCS12 -jar app.jar
```

Acest truststore conține *doar* CA-ul MiniCA. Pentru a adăuga CA-ul în store-ul
implicit al JDK-ului (ca CA-urile publice să continue să funcționeze):

```sh
keytool -importcert -trustcacerts -noprompt -alias minica \
  -file minica-ca.pem -cacerts -storepass changeit
```

Clienții Kafka folosesc `ssl.truststore.location=minica-truststore.p12`,
`ssl.truststore.password=changeit`, `ssl.truststore.type=PKCS12`.

### Go

Go folosește store-ul sistemului (`crypto/x509` citește `/etc/ssl/certs` pe Linux) și
respectă `SSL_CERT_FILE` / `SSL_CERT_DIR`. Pentru a adăuga un CA din cod:

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

Aceasta *adaugă* la CA-urile incluse în Node. `--use-openssl-ca` face ca Node să folosească
în schimb store-ul sistemului.

### yt-dlp

yt-dlp este un program Python și urmează regulile Python: dacă `certifi` este
instalat (cazul obișnuit), folosește bundle-ul certifi, altfel store-ul implicit
OpenSSL. Fie instalați CA-ul în store-ul sistemului și eliminați /
ocoliți certifi, fie îndreptați stack-ul HTTP al yt-dlp spre un bundle care le conține pe ambele:

```sh
cat "$(python3 -m certifi)" minica-ca.pem > ~/.config/yt-dlp/ca-bundle.pem
SSL_CERT_FILE=~/.config/yt-dlp/ca-bundle.pem REQUESTS_CA_BUNDLE=~/.config/yt-dlp/ca-bundle.pem yt-dlp https://media.intranet.example.com/...
```

Evitați `--no-check-certificates`; dezactivează complet verificarea.

## Servere și servicii

### Nginx

Trei lucruri diferite se confundă ușor:

- **Servirea unui certificat emis de MiniCA.** Descărcați *Bundle*-ul
  certificatului (zip) — `cert.pem`, `cert.key` și `ca.pem` — și folosiți
  ```nginx
  ssl_certificate     /etc/nginx/tls/cert.pem;    # or cat cert.pem ca.pem > fullchain.pem
  ssl_certificate_key /etc/nginx/tls/cert.key;
  ```
  Clienții trebuie apoi să aibă CA-ul instalat, așa cum este descris în această pagină.
- **Nginx ca client TLS** (proxy către un upstream care prezintă un
  certificat MiniCA):
  ```nginx
  proxy_ssl_verify on;
  proxy_ssl_trusted_certificate /etc/nginx/tls/minica-ca.pem;
  proxy_ssl_name upstream.example.com;
  ```
- **Certificate client (mTLS) emise de MiniCA:**
  ```nginx
  ssl_client_certificate /etc/nginx/tls/minica-ca.pem;
  ssl_verify_client on;
  ssl_crl /etc/nginx/tls/minica.crl.pem;   # optional: openssl crl -inform DER -in <crl> -out minica.crl.pem
  ```
  CRL-ul se află la `https://ca.example.com/minica/crl/<ca-id>` (DER).

### Docker

Pentru o **imagine**, adăugați CA-ul la momentul build-ului, astfel încât fiecare instrument din imagine să îl vadă:

```dockerfile
# Debian/Ubuntu based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN update-ca-certificates
# Alpine based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN apk add --no-cache ca-certificates && update-ca-certificates
```

Pentru un **container pe care nu îl puteți reconstrui**, montați un bundle care conține deja
CA-ul (de ex. `/etc/ssl/certs/ca-certificates.crt` al gazdei, după instalarea
CA-ului pe gazdă) peste bundle-ul imaginii, sau îndreptați instrumentele dinăuntru spre el
prin variabilele de mediu de mai sus:

```yaml
    environment:
      SSL_CERT_FILE:        /etc/ssl/certs/ca-certificates.crt   # OpenSSL, Python ssl, Go, Ruby
      REQUESTS_CA_BUNDLE:   /etc/ssl/certs/ca-certificates.crt   # Python requests
      CURL_CA_BUNDLE:       /etc/ssl/certs/ca-certificates.crt   # curl
      NODE_EXTRA_CA_CERTS:  /etc/ssl/certs/ca-certificates.crt   # Node.js
    volumes:
      - /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro
```

Imaginile bazate pe distribuții care păstrează bundle-ul în altă parte
(familia RHEL: `/etc/pki/tls/certs/ca-bundle.crt`) au nevoie de acea cale.

*Daemon*-ul Docker se încrede în CA-ul unui registry privat din
`/etc/docker/certs.d/<registry:port>/ca.crt`, independent de store-ul sistemului.

### LLDAP

LLDAP este un server: oferiți-i un certificat emis de MiniCA pentru
listener-ul său LDAPS (descărcați bundle-ul certificatului; cheia este `cert.key`):

```toml
# lldap_config.toml
[ldaps_options]
enabled = true
port = 6360
cert_file = "/data/tls/cert.pem"
key_file = "/data/tls/cert.key"
```

sau `LLDAP_LDAPS_OPTIONS__ENABLED=true`, `LLDAP_LDAPS_OPTIONS__CERT_FILE=...`,
`LLDAP_LDAPS_OPTIONS__KEY_FILE=...` în mediu. Fiecare client LDAP
(Authelia, Nextcloud, Jellyfin, ...) are apoi nevoie de CA-ul MiniCA în propriul
trust store, conform rețetelor de mai sus pentru platforma sau limbajul în care rulează.

## Publicarea MiniCA prin Nginx

Cu autentificarea proprie MiniCA, un singur prefix este suficient. MiniCA își protejează singur paginile private, iar acest ghid rămâne public la `/minica/how-to-use`:

```nginx
location /minica/ {
    proxy_pass http://minica:9988;
    include /etc/nginx/snippets/proxy.conf;
}
```

Cu SSO (Authelia, oauth2-proxy, ...), prefixul este protejat, deci paginile publice au nevoie de o regulă separată. Păstrați antetele de identitate golite în acea regulă, deoarece MiniCA are încredere în ele atunci când vin de la proxy:

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

## Verificarea funcționării

```sh
openssl s_client -connect intranet.example.com:443 -servername intranet.example.com </dev/null 2>/dev/null | grep "Verify return code"
curl -v https://intranet.example.com/ 2>&1 | grep -E "SSL certificate verify|issuer"
```

`Verify return code: 0 (ok)` înseamnă că clientul a găsit CA-ul și are încredere în el.
