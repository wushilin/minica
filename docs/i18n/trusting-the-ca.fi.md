<!-- source-sha256: 51e546526752332fcfc280e7dff9c74d662f180be9dc12f325b1f7754935dbb2 -->
# MiniCA-varmentajan luottaminen

MiniCA:n myöntämät varmenteet kelpaavat asiakkaalle vasta, kun asiakas
luottaa myöntävään CA:han. Tälle sivulle on koottu ohjeet yleisimmille
alustoille ja työkaluille. Kaikki lähtee liikkeelle kahdesta julkisesta
latauksesta, jotka jokaisella CA:lla on (kirjautumista ei tarvita):

| Lataus | URL | Käyttökohde |
| --- | --- | --- |
| CA-varmenne (PEM) | `https://ca.example.com/minica/<ca-id>/download` | kaikki paitsi Java |
| CA:n luottamusvarasto (PKCS#12, salasana `changeit`) | `https://ca.example.com/minica/download/ca/<ca-id>/truststore` | Java- / JVM-sovellukset |

Molemmat on linkitetty myös julkiseen CA-hakemistoon osoitteessa `https://ca.example.com/minica/`
sekä CA:n omalle sivulle. Tiedosto nimetään CA:n yleisen nimen mukaan, esim.
`Homelab_CA.pem`; alla olevissa esimerkeissä siitä käytetään nimeä `minica-ca.pem` / `minica-ca.crt`.

```sh
curl -fsSLo minica-ca.pem https://ca.example.com/minica/<ca-id>/download
openssl x509 -in minica-ca.pem -noout -subject -dates -fingerprint -sha256   # check what you got
```

Asiakkaille asennetaan aina vain **CA-varmenne** — ei koskaan yksityistä
avainta. Jos CA on välivarmentaja, asenna sen juurivarmenne (tai myös se).

## Käyttöjärjestelmät

### Debian / Ubuntu

```sh
sudo cp minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt   # must end in .crt, PEM content
sudo update-ca-certificates
```

Tämä lisää CA:n tiedostoon `/etc/ssl/certs/ca-certificates.crt`, jota curl, wget,
Python, Go, Node (`NODE_EXTRA_CA_CERTS`-muuttujalla tai `--use-openssl-ca`-valitsimella), apt ja
useimmat muut järjestelmän ohjelmat käyttävät. Hakemisto `/usr/local/share/ca-certificates/`
on oikea paikka paikallisille lisäyksille; `/usr/share/ca-certificates/` kuuluu
jakelun paketille.

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

(Suorita ensin `apk add ca-certificates`, jos `update-ca-certificates` puuttuu.)

### Arch Linux

```sh
sudo trust anchor --store minica-ca.pem
```

### macOS

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain minica-ca.pem
```

Tai kaksoisnapsauta tiedostoa, lisää se Keychain Accessissa *System*-avainnippuun,
avaa se ja aseta *When using this certificate* -asetukseksi *Always Trust*. Safari ja
Chrome käyttävät avainnippua; Firefox tarvitsee alla olevan lisävaiheen.

### Windows

Järjestelmänvalvojana (PowerShell):

```powershell
Import-Certificate -FilePath .\minica-ca.pem -CertStoreLocation Cert:\LocalMachine\Root
```

tai `certutil -addstore -f Root minica-ca.pem`, tai kaksoisnapsauta → *Install
Certificate* → *Local Machine* → *Place all certificates in the following
store* → *Trusted Root Certification Authorities*. Edge, Chrome ja
.NET/PowerShell käyttävät tätä varastoa; Firefox tarvitsee alla olevan lisävaiheen.

### Android

Android asentaa vain DER- tai PEM-tiedostoja, joiden nimi päättyy `.crt`/`.cer`:

```sh
openssl x509 -in minica-ca.pem -outform DER -out minica-ca.crt
```

Kopioi tiedosto puhelimeen ja valitse *Settings → Security → Encryption & credentials →
Install a certificate → CA certificate*. Android 11+ varoittaa, että
varmenne on asennettava Asetuksista; se on yllä oleva polku.
Chrome ja useimmat sovellukset luottavat siihen tämän jälkeen, mutta sovellukset, jotka kiinnittävät varmenteita (pinning) tai sisältävät
oman luottamusvarastonsa (ja jotkin, jotka käyttävät omaa verkkopinoaan), eivät luota.

### iOS / iPadOS

Avaa `.pem` laitteella (AirDrop, Mail, Files) → *Settings → Profile
Downloaded → Install*, ja ota se sitten käyttöön kohdassa *Settings → General → About →
Certificate Trust Settings*.

## Selaimet

Chrome, Edge ja Safari käyttävät käyttöjärjestelmän varastoa, joten yllä olevat vaiheet
riittävät. **Firefox** pitää oman varastonsa, ellei toisin määrätä:

- Preferences → Privacy & Security → Certificates → *View Certificates* →
  *Authorities* → *Import* → rastita *Trust this CA to identify websites*; tai
- aseta `security.enterprise_roots.enabled` arvoon `true` osoitteessa `about:config`, jotta
  Firefox käyttää Windowsin / macOS:n järjestelmävarastoa; tai
- Linuxissa tuo profiilin NSS-tietokantaan:
  `certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.mozilla/firefox/<profile>` (`certutil` tulee paketista `libnss3-tools` / `nss-tools`).

Linuxin Chromiumilla on myös NSS-varasto käyttäjän asentamille CA:ille:
`certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.pki/nssdb`.

## Komentorivityökalut ja ohjelmointikielet

### curl

```sh
curl --cacert minica-ca.pem https://intranet.example.com/
export CURL_CA_BUNDLE=/path/to/minica-ca.pem     # for a shell session
```

Kun CA on asennettu järjestelmävarastoon (yllä), valitsinta ei tarvita.
`CURL_CA_BUNDLE` *korvaa* paketin, joten osoita se tiedostoon, joka sisältää myös
julkiset CA:t, jos tarvitset molempia (esim. liitä MiniCA:n PEM kopion loppuun tiedostosta
`/etc/ssl/certs/ca-certificates.crt`).

### wget

```sh
wget --ca-certificate=minica-ca.pem https://intranet.example.com/
echo "ca_certificate = /path/to/minica-ca.pem" >> ~/.wgetrc
```

### Python

`urllib`, `http.client` ja `ssl`-moduuli käyttävät OpenSSL:n oletuspolkuja,
eli järjestelmävarastoa, ja noudattavat muuttujia `SSL_CERT_FILE` / `SSL_CERT_DIR`. Kirjasto
`requests` (ja kaikki sen päälle rakennettu, `pip` mukaan lukien) käyttää sen sijaan
`certifi`-pakettia:

```sh
export REQUESTS_CA_BUNDLE=/path/to/minica-ca.pem   # requests; replaces the bundle
export SSL_CERT_FILE=/path/to/minica-ca.pem        # ssl / urllib / httpx
pip config set global.cert /path/to/minica-ca.pem  # pip
```

Jos haluat säilyttää myös julkiset CA:t, liitä MiniCA:n PEM certifin paketin
kopion loppuun (`python -m certifi` tulostaa sen polun) ja osoita muuttujat
kopioon. `pip install pip-system-certs` tai `truststore` saa requestsin
käyttämään käyttöjärjestelmän varastoa.

### Java / JVM (Kafka, Elasticsearch, Jenkins, ...)

CA:n luottamusvarasto -lataus on käyttövalmis PKCS#12-luottamusvarasto (salasana
`changeit`, CA tallennettuna `trustedCertEntry`-merkintänä):

```sh
curl -fsSLo minica-truststore.p12 https://ca.example.com/minica/download/ca/<ca-id>/truststore
java -Djavax.net.ssl.trustStore=minica-truststore.p12 \
     -Djavax.net.ssl.trustStorePassword=changeit \
     -Djavax.net.ssl.trustStoreType=PKCS12 -jar app.jar
```

Tämä luottamusvarasto sisältää *vain* MiniCA:n CA:n. Jos haluat lisätä CA:n JDK:n
oletusvarastoon (jotta julkiset CA:t toimivat edelleen):

```sh
keytool -importcert -trustcacerts -noprompt -alias minica \
  -file minica-ca.pem -cacerts -storepass changeit
```

Kafka-asiakkaat käyttävät asetuksia `ssl.truststore.location=minica-truststore.p12`,
`ssl.truststore.password=changeit`, `ssl.truststore.type=PKCS12`.

### Go

Go käyttää järjestelmävarastoa (`crypto/x509` lukee Linuxissa `/etc/ssl/certs`) ja
noudattaa muuttujia `SSL_CERT_FILE` / `SSL_CERT_DIR`. CA:n lisääminen koodista:

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

Tämä *lisää* CA:t Noden mukana tulevien CA:iden joukkoon. `--use-openssl-ca` saa Noden
käyttämään järjestelmävarastoa sen sijaan.

### yt-dlp

yt-dlp on Python-ohjelma ja noudattaa Pythonin sääntöjä: jos `certifi`
on asennettu (yleinen tapaus), se käyttää certifin pakettia, muuten OpenSSL:n
oletusvarastoa. Joko asenna CA järjestelmävarastoon ja poista / ohita
certifi, tai osoita yt-dlp:n HTTP-pino pakettiin, joka sisältää molemmat:

```sh
cat "$(python3 -m certifi)" minica-ca.pem > ~/.config/yt-dlp/ca-bundle.pem
SSL_CERT_FILE=~/.config/yt-dlp/ca-bundle.pem REQUESTS_CA_BUNDLE=~/.config/yt-dlp/ca-bundle.pem yt-dlp https://media.intranet.example.com/...
```

Vältä `--no-check-certificates`-valitsinta; se poistaa tarkistuksen kokonaan käytöstä.

## Palvelimet ja palvelut

### Nginx

Kolme eri asiaa menee helposti sekaisin:

- **MiniCA:n myöntämän varmenteen tarjoaminen.** Lataa varmenteen
  *Bundle* (zip) — `cert.pem`, `cert.key` ja `ca.pem` — ja käytä
  ```nginx
  ssl_certificate     /etc/nginx/tls/cert.pem;    # or cat cert.pem ca.pem > fullchain.pem
  ssl_certificate_key /etc/nginx/tls/cert.key;
  ```
  Asiakkaiden täytyy tämän jälkeen asentaa CA tällä sivulla kuvatulla tavalla.
- **Nginx TLS-asiakkaana** (välitys taustapalvelimelle, joka esittää
  MiniCA-varmenteen):
  ```nginx
  proxy_ssl_verify on;
  proxy_ssl_trusted_certificate /etc/nginx/tls/minica-ca.pem;
  proxy_ssl_name upstream.example.com;
  ```
- **MiniCA:n myöntämät asiakasvarmenteet (mTLS):**
  ```nginx
  ssl_client_certificate /etc/nginx/tls/minica-ca.pem;
  ssl_verify_client on;
  ssl_crl /etc/nginx/tls/minica.crl.pem;   # optional: openssl crl -inform DER -in <crl> -out minica.crl.pem
  ```
  CRL on osoitteessa `https://ca.example.com/minica/crl/<ca-id>` (DER).

### Docker

**Imagen** kohdalla lisää CA koontivaiheessa, jotta jokainen imagen työkalu näkee sen:

```dockerfile
# Debian/Ubuntu based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN update-ca-certificates
# Alpine based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN apk add --no-cache ca-certificates && update-ca-certificates
```

**Kontille, jota et voi koota uudelleen**, liitä (mount) paketti, joka jo sisältää
CA:n (esim. isännän `/etc/ssl/certs/ca-certificates.crt` sen jälkeen, kun CA on asennettu
isännälle) imagen paketin päälle, tai osoita sisällä olevat työkalut siihen
yllä mainituilla ympäristömuuttujilla:

```yaml
    environment:
      SSL_CERT_FILE:        /etc/ssl/certs/ca-certificates.crt   # OpenSSL, Python ssl, Go, Ruby
      REQUESTS_CA_BUNDLE:   /etc/ssl/certs/ca-certificates.crt   # Python requests
      CURL_CA_BUNDLE:       /etc/ssl/certs/ca-certificates.crt   # curl
      NODE_EXTRA_CA_CERTS:  /etc/ssl/certs/ca-certificates.crt   # Node.js
    volumes:
      - /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro
```

Imaget, jotka perustuvat jakeluihin, joissa paketti sijaitsee muualla
(RHEL-perhe: `/etc/pki/tls/certs/ca-bundle.crt`), tarvitsevat sen polun.

Dockerin *daemon* luottaa yksityisen rekisterin CA:han polusta
`/etc/docker/certs.d/<registry:port>/ca.crt`, järjestelmävarastosta riippumatta.

### LLDAP

LLDAP on palvelin: anna sille MiniCA:n myöntämä varmenne sen LDAPS-kuuntelijaa
varten (lataa varmenteen paketti; avain on `cert.key`):

```toml
# lldap_config.toml
[ldaps_options]
enabled = true
port = 6360
cert_file = "/data/tls/cert.pem"
key_file = "/data/tls/cert.key"
```

tai `LLDAP_LDAPS_OPTIONS__ENABLED=true`, `LLDAP_LDAPS_OPTIONS__CERT_FILE=...`,
`LLDAP_LDAPS_OPTIONS__KEY_FILE=...` ympäristössä. Jokainen LDAP-asiakas
(Authelia, Nextcloud, Jellyfin, ...) tarvitsee tämän jälkeen MiniCA:n CA:n omaan
luottamusvarastoonsa, kuten yllä on ohjeistettu sille alustalle tai kielelle, jolla se toimii.

## MiniCA:n julkaiseminen Nginxin kautta

MiniCA:n omalla kirjautumisella yksi etuliite riittää. MiniCA suojaa yksityiset sivunsa itse, ja tämä ohje pysyy julkisena osoitteessa `/minica/how-to-use`:

```nginx
location /minica/ {
    proxy_pass http://minica:9988;
    include /etc/nginx/snippets/proxy.conf;
}
```

SSO:n (Authelia, oauth2-proxy, ...) kanssa etuliite on suojattu, joten julkiset sivut tarvitsevat oman sääntönsä. Pidä identiteettiotsikot tyhjennettyinä tässä säännössä, koska MiniCA luottaa niihin, kun ne tulevat välityspalvelimelta:

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

## Toimivuuden tarkistaminen

```sh
openssl s_client -connect intranet.example.com:443 -servername intranet.example.com </dev/null 2>/dev/null | grep "Verify return code"
curl -v https://intranet.example.com/ 2>&1 | grep -E "SSL certificate verify|issuer"
```

`Verify return code: 0 (ok)` tarkoittaa, että asiakas löysi CA:n ja luottaa siihen.
