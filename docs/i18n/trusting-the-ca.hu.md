<!-- source-sha256: 51e546526752332fcfc280e7dff9c74d662f180be9dc12f325b1f7754935dbb2 -->
# MiniCA hitelesítésszolgáltató megbízhatóvá tétele

A MiniCA által kiállított tanúsítványokat egy kliens csak akkor fogadja el,
ha megbízik a kiállító CA-ban. Ez az oldal a gyakori platformokhoz és
eszközökhöz gyűjti össze a lépéseket. Minden két nyilvános letöltésből indul,
amely minden CA-nál elérhető (bejelentkezés nélkül):

| Letöltés | URL | Mire használható |
| --- | --- | --- |
| CA-tanúsítvány (PEM) | `https://ca.example.com/minica/<ca-id>/download` | minden, kivéve a Java |
| CA-tanúsítványtár (PKCS#12, jelszó: `changeit`) | `https://ca.example.com/minica/download/ca/<ca-id>/truststore` | Java / JVM alkalmazások |

Mindkettőre hivatkozik a nyilvános CA-index a `https://ca.example.com/minica/`
címen, valamint a CA oldala. A fájl neve a CA common name értékéből készül,
pl. `Homelab_CA.pem`; az alábbi példák `minica-ca.pem` / `minica-ca.crt` néven
hivatkoznak rá.

```sh
curl -fsSLo minica-ca.pem https://ca.example.com/minica/<ca-id>/download
openssl x509 -in minica-ca.pem -noout -subject -dates -fingerprint -sha256   # check what you got
```

Az ügyfeleken kizárólag a **CA-tanúsítványt** kell telepíteni — privát kulcsot soha.
Ha a CA köztes (intermediate) CA, a gyökér CA-t telepítse helyette (vagy mellé).

## Operációs rendszerek

### Debian / Ubuntu

```sh
sudo cp minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt   # must end in .crt, PEM content
sudo update-ca-certificates
```

Ez felveszi a CA-t a `/etc/ssl/certs/ca-certificates.crt` fájlba, amelyet a
curl, a wget, a Python, a Go, a Node (a `NODE_EXTRA_CA_CERTS` vagy a
`--use-openssl-ca` használatával), az apt és a rendszer legtöbb más programja
használ. A `/usr/local/share/ca-certificates/` a helyi kiegészítések megfelelő
helye; a `/usr/share/ca-certificates/` a disztribúció csomagjához tartozik.

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

(Ha az `update-ca-certificates` hiányzik, először futtassa az `apk add ca-certificates` parancsot.)

### Arch Linux

```sh
sudo trust anchor --store minica-ca.pem
```

### macOS

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain minica-ca.pem
```

Vagy kattintson duplán a fájlra, adja hozzá a *System* kulcskarikához a Keychain Accessben,
nyissa meg, és állítsa a *When using this certificate* beállítást *Always Trust* értékre. A Safari és
a Chrome a kulcskarikát használja; a Firefoxhoz az alábbi extra lépés kell.

### Windows

Rendszergazdaként (PowerShell):

```powershell
Import-Certificate -FilePath .\minica-ca.pem -CertStoreLocation Cert:\LocalMachine\Root
```

vagy `certutil -addstore -f Root minica-ca.pem`, vagy kattintson duplán → *Install
Certificate* → *Local Machine* → *Place all certificates in the following
store* → *Trusted Root Certification Authorities*. Az Edge, a Chrome és a
.NET/PowerShell ezt a tárolót használja; a Firefoxhoz az alábbi extra lépés kell.

### Android

Az Android csak `.crt`/`.cer` nevű DER vagy PEM fájlokat telepít:

```sh
openssl x509 -in minica-ca.pem -outform DER -out minica-ca.crt
```

Másolja át a telefonra, majd: *Settings → Security → Encryption & credentials →
Install a certificate → CA certificate*. Android 11-től figyelmeztet, hogy a
tanúsítványt a Beállításokból kell telepíteni; ez a fenti útvonal.
A Chrome és a legtöbb alkalmazás ezután megbízik benne, de azok az alkalmazások, amelyek
rögzítik a tanúsítványokat (pinning) vagy saját tanúsítványtárat tartalmaznak (és néhány,
amely saját hálózati réteget használ), nem fognak.

### iOS / iPadOS

Nyissa meg a `.pem` fájlt az eszközön (AirDrop, Mail, Files) → *Settings → Profile
Downloaded → Install*, majd engedélyezze itt: *Settings → General → About →
Certificate Trust Settings*.

## Böngészők

A Chrome, az Edge és a Safari az operációs rendszer tárolóját használja, így a fenti
lépések elegendők. A **Firefox** külön tárolót tart fenn, hacsak másként nem állítják be:

- Preferences → Privacy & Security → Certificates → *View Certificates* →
  *Authorities* → *Import* → jelölje be a *Trust this CA to identify websites* opciót; vagy
- állítsa az `about:config` oldalon a `security.enterprise_roots.enabled` értéket `true`-ra, hogy
  a Firefox a Windows / macOS rendszertárolót használja; vagy
- Linuxon importálja a profil NSS-adatbázisába:
  `certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.mozilla/firefox/<profile>` (a `certutil` a `libnss3-tools` / `nss-tools` csomagból).

A Chromium Linuxon a felhasználó által telepített CA-khoz szintén NSS-tárolót használ:
`certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.pki/nssdb`.

## Parancssori eszközök és nyelvek

### curl

```sh
curl --cacert minica-ca.pem https://intranet.example.com/
export CURL_CA_BUNDLE=/path/to/minica-ca.pem     # for a shell session
```

A CA rendszertárolóba telepítése után (lásd fent) nincs szükség kapcsolóra.
A `CURL_CA_BUNDLE` *lecseréli* a csomagot, ezért olyan fájlra mutasson, amely a
nyilvános CA-kat is tartalmazza, ha mindkettőre szüksége van (pl. fűzze a MiniCA PEM-et az
`/etc/ssl/certs/ca-certificates.crt` egy másolatához).

### wget

```sh
wget --ca-certificate=minica-ca.pem https://intranet.example.com/
echo "ca_certificate = /path/to/minica-ca.pem" >> ~/.wgetrc
```

### Python

Az `urllib`, a `http.client` és az `ssl` modul az OpenSSL alapértelmezett útvonalait,
vagyis a rendszertárolót használja, és figyelembe veszi az `SSL_CERT_FILE` / `SSL_CERT_DIR` változót. A
`requests` könyvtár (és minden, ami rá épül, a `pip` is) ehelyett a
`certifi` csomagot használja:

```sh
export REQUESTS_CA_BUNDLE=/path/to/minica-ca.pem   # requests; replaces the bundle
export SSL_CERT_FILE=/path/to/minica-ca.pem        # ssl / urllib / httpx
pip config set global.cert /path/to/minica-ca.pem  # pip
```

A nyilvános CA-k megtartásához fűzze a MiniCA PEM-et a certifi csomagjának egy másolatához
(a `python -m certifi` kiírja az útvonalát), és a változókat a másolatra irányítsa.
A `pip install pip-system-certs` vagy a `truststore` hatására a requests az
operációs rendszer tárolóját használja.

### Java / JVM (Kafka, Elasticsearch, Jenkins, ...)

A CA-tanúsítványtár letöltése egy azonnal használható PKCS#12 tanúsítványtár (jelszó:
`changeit`, a CA `trustedCertEntry` bejegyzésként tárolva):

```sh
curl -fsSLo minica-truststore.p12 https://ca.example.com/minica/download/ca/<ca-id>/truststore
java -Djavax.net.ssl.trustStore=minica-truststore.p12 \
     -Djavax.net.ssl.trustStorePassword=changeit \
     -Djavax.net.ssl.trustStoreType=PKCS12 -jar app.jar
```

Ez a tanúsítványtár *csak* a MiniCA CA-t tartalmazza. Ha a CA-t inkább a JDK
alapértelmezett tárolójához adja hozzá (hogy a nyilvános CA-k továbbra is működjenek):

```sh
keytool -importcert -trustcacerts -noprompt -alias minica \
  -file minica-ca.pem -cacerts -storepass changeit
```

A Kafka kliensek ezt használják: `ssl.truststore.location=minica-truststore.p12`,
`ssl.truststore.password=changeit`, `ssl.truststore.type=PKCS12`.

### Go

A Go a rendszertárolót használja (a `crypto/x509` Linuxon az `/etc/ssl/certs` könyvtárat olvassa), és
figyelembe veszi az `SSL_CERT_FILE` / `SSL_CERT_DIR` változót. CA hozzáadása kódból:

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

Ez *hozzáadja* a CA-t a Node beépített CA-ihoz. A `--use-openssl-ca` hatására a Node
a rendszertárolót használja.

### yt-dlp

A yt-dlp Python program, ezért a Python szabályai érvényesek rá: ha a `certifi`
telepítve van (ez a szokásos), annak csomagját használja, különben az OpenSSL
alapértelmezett tárolóját. Vagy telepítse a CA-t a rendszertárolóba, és távolítsa el /
kerülje meg a certifit, vagy irányítsa a yt-dlp HTTP-rétegét egy mindkettőt tartalmazó csomagra:

```sh
cat "$(python3 -m certifi)" minica-ca.pem > ~/.config/yt-dlp/ca-bundle.pem
SSL_CERT_FILE=~/.config/yt-dlp/ca-bundle.pem REQUESTS_CA_BUNDLE=~/.config/yt-dlp/ca-bundle.pem yt-dlp https://media.intranet.example.com/...
```

Kerülje a `--no-check-certificates` kapcsolót; az teljesen kikapcsolja az ellenőrzést.

## Szerverek és szolgáltatások

### Nginx

Három különböző dolog könnyen összekeverhető:

- **MiniCA által kiállított tanúsítvány kiszolgálása.** Töltse le a tanúsítvány
  *Bundle* (zip) csomagját — `cert.pem`, `cert.key` és `ca.pem` — és használja így
  ```nginx
  ssl_certificate     /etc/nginx/tls/cert.pem;    # or cat cert.pem ca.pem > fullchain.pem
  ssl_certificate_key /etc/nginx/tls/cert.key;
  ```
  A kliensekre ezután az ezen az oldalon leírt módon kell telepíteni a CA-t.
- **Az Nginx mint TLS-kliens** (olyan upstreamhez proxyzva, amely MiniCA
  tanúsítványt mutat):
  ```nginx
  proxy_ssl_verify on;
  proxy_ssl_trusted_certificate /etc/nginx/tls/minica-ca.pem;
  proxy_ssl_name upstream.example.com;
  ```
- **A MiniCA által kiállított kliens-tanúsítványok (mTLS):**
  ```nginx
  ssl_client_certificate /etc/nginx/tls/minica-ca.pem;
  ssl_verify_client on;
  ssl_crl /etc/nginx/tls/minica.crl.pem;   # optional: openssl crl -inform DER -in <crl> -out minica.crl.pem
  ```
  A CRL a `https://ca.example.com/minica/crl/<ca-id>` címen érhető el (DER).

### Docker

Egy **image** esetén a CA-t build időben adja hozzá, hogy az image minden eszköze lássa:

```dockerfile
# Debian/Ubuntu based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN update-ca-certificates
# Alpine based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN apk add --no-cache ca-certificates && update-ca-certificates
```

Egy **nem újraépíthető konténernél** csatoljon be egy olyan csomagot, amely már tartalmazza
a CA-t (pl. a gazdagép `/etc/ssl/certs/ca-certificates.crt` fájlját, miután a gazdagépen
telepítette a CA-t) az image csomagja helyére, vagy irányítsa rá a bent futó eszközöket
a fenti környezeti változókkal:

```yaml
    environment:
      SSL_CERT_FILE:        /etc/ssl/certs/ca-certificates.crt   # OpenSSL, Python ssl, Go, Ruby
      REQUESTS_CA_BUNDLE:   /etc/ssl/certs/ca-certificates.crt   # Python requests
      CURL_CA_BUNDLE:       /etc/ssl/certs/ca-certificates.crt   # curl
      NODE_EXTRA_CA_CERTS:  /etc/ssl/certs/ca-certificates.crt   # Node.js
    volumes:
      - /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro
```

Azoknál az image-eknél, amelyek disztribúciója a csomagot máshol tartja
(RHEL-család: `/etc/pki/tls/certs/ca-bundle.crt`), azt az útvonalat kell megadni.

A Docker *démon* a privát registry CA-jában a
`/etc/docker/certs.d/<registry:port>/ca.crt` fájlból bízik meg, a rendszertárolótól függetlenül.

### LLDAP

Az LLDAP egy szerver: adjon neki MiniCA által kiállított tanúsítványt az LDAPS
figyelőjéhez (töltse le a tanúsítvány csomagját; a kulcs a `cert.key`):

```toml
# lldap_config.toml
[ldaps_options]
enabled = true
port = 6360
cert_file = "/data/tls/cert.pem"
key_file = "/data/tls/cert.key"
```

vagy a környezetben `LLDAP_LDAPS_OPTIONS__ENABLED=true`, `LLDAP_LDAPS_OPTIONS__CERT_FILE=...`,
`LLDAP_LDAPS_OPTIONS__KEY_FILE=...`. Minden LDAP-kliensnek (Authelia, Nextcloud, Jellyfin, ...)
ezután szüksége van a MiniCA CA-ra a saját tanúsítványtárában, a futtató platformra
vagy nyelvre vonatkozó fenti receptek szerint.

## A MiniCA közzététele Nginxen keresztül

A MiniCA saját bejelentkezésével egy előtag elég. A MiniCA maga védi a privát oldalait, ez az útmutató pedig nyilvános marad a `/minica/how-to-use` címen:

```nginx
location /minica/ {
    proxy_pass http://minica:9988;
    include /etc/nginx/snippets/proxy.conf;
}
```

SSO esetén (Authelia, oauth2-proxy, ...) az előtag védett, ezért a nyilvános oldalakhoz külön szabály kell. Tartsa törölve az identitásfejléceket ezen a szabályon, mert a MiniCA megbízik bennük, ha a proxytól érkeznek:

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

## Működésének ellenőrzése

```sh
openssl s_client -connect intranet.example.com:443 -servername intranet.example.com </dev/null 2>/dev/null | grep "Verify return code"
curl -v https://intranet.example.com/ 2>&1 | grep -E "SSL certificate verify|issuer"
```

A `Verify return code: 0 (ok)` azt jelenti, hogy a kliens megtalálta a CA-t, és megbízik benne.
