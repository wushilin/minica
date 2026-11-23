<!-- source-sha256: 51e546526752332fcfc280e7dff9c74d662f180be9dc12f325b1f7754935dbb2 -->
# Поверење у MiniCA сертификациони орган

Сертификате које издаје MiniCA клијент прихвата тек када верује издавачком
CA-у. Ова страница садржи рецепте за уобичајене платформе и алате. Све
почиње од два јавна преузимања која има сваки CA (пријава није потребна):

| Преузимање | URL | Користи се за |
| --- | --- | --- |
| CA сертификат (PEM) | `https://ca.example.com/minica/<ca-id>/download` | све осим Јаве |
| CA truststore (PKCS#12, лозинка `changeit`) | `https://ca.example.com/minica/download/ca/<ca-id>/truststore` | Java / JVM апликације |

Оба су повезана и са јавног CA индекса на `https://ca.example.com/minica/`
и са странице CA-а. Датотека се зове по common name-у CA-а, нпр.
`Homelab_CA.pem`; примери у наставку зову је `minica-ca.pem` / `minica-ca.crt`.

```sh
curl -fsSLo minica-ca.pem https://ca.example.com/minica/<ca-id>/download
openssl x509 -in minica-ca.pem -noout -subject -dates -fingerprint -sha256   # check what you got
```

На клијенте се инсталира само **CA сертификат** — никада приватни
кључ. Ако је CA посредни, инсталирајте његов корени CA (или и њега).

## Оперативни системи

### Debian / Ubuntu

```sh
sudo cp minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt   # must end in .crt, PEM content
sudo update-ca-certificates
```

Ово додаје CA у `/etc/ssl/certs/ca-certificates.crt`, који користе curl, wget,
Python, Go, Node (са `NODE_EXTRA_CA_CERTS` или `--use-openssl-ca`), apt и
већина осталих програма на систему. `/usr/local/share/ca-certificates/`
је право место за локалне додатке; `/usr/share/ca-certificates/` припада
пакету дистрибуције.

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

(Прво `apk add ca-certificates` ако `update-ca-certificates` недостаје.)

### Arch Linux

```sh
sudo trust anchor --store minica-ca.pem
```

### macOS

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain minica-ca.pem
```

Или двоструко кликните на датотеку, додајте је у *System* keychain у Keychain
Access-у, отворите је и поставите *When using this certificate* на *Always Trust*.
Safari и Chrome користе keychain; Firefox захтева додатни корак у наставку.

### Windows

Као администратор (PowerShell):

```powershell
Import-Certificate -FilePath .\minica-ca.pem -CertStoreLocation Cert:\LocalMachine\Root
```

или `certutil -addstore -f Root minica-ca.pem`, или двоструки клик → *Install
Certificate* → *Local Machine* → *Place all certificates in the following
store* → *Trusted Root Certification Authorities*. Edge, Chrome и
.NET/PowerShell користе ово складиште; Firefox захтева додатни корак у наставку.

### Android

Android инсталира само DER или PEM датотеке са називом `.crt`/`.cer`:

```sh
openssl x509 -in minica-ca.pem -outform DER -out minica-ca.crt
```

Копирајте је на телефон, затим *Settings → Security → Encryption & credentials →
Install a certificate → CA certificate*. Android 11+ упозорава да сертификат
мора бити инсталиран из Подешавања; то је горе наведена путања.
Chrome и већина апликација му тада верује, али апликације које пинују
сертификате или имају сопствено складиште поверења (и неке које користе
сопствени мрежни стек) неће.

### iOS / iPadOS

Отворите `.pem` на уређају (AirDrop, Mail, Files) → *Settings → Profile
Downloaded → Install*, а затим га омогућите у *Settings → General → About →
Certificate Trust Settings*.

## Прегледачи

Chrome, Edge и Safari користе складиште оперативног система, па су горњи
кораци довољни. **Firefox** има своје складиште ако му се не каже другачије:

- Preferences → Privacy & Security → Certificates → *View Certificates* →
  *Authorities* → *Import* → означите *Trust this CA to identify websites*; или
- поставите `security.enterprise_roots.enabled` на `true` у `about:config` да
  Firefox користи системско складиште Windows-а / macOS-а; или
- на Linux-у, увезите у NSS базу профила:
  `certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.mozilla/firefox/<profile>` (`certutil` из `libnss3-tools` / `nss-tools`).

Chromium на Linux-у такође има NSS складиште за CA-ове које инсталира корисник:
`certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.pki/nssdb`.

## Алати командне линије и језици

### curl

```sh
curl --cacert minica-ca.pem https://intranet.example.com/
export CURL_CA_BUNDLE=/path/to/minica-ca.pem     # for a shell session
```

Након инсталације CA-а у системско складиште (горе) није потребна ниједна опција.
`CURL_CA_BUNDLE` *замењује* пакет, па га усмерите на датотеку која садржи и
јавне CA-ове ако вам требају оба (нпр. додајте MiniCA PEM на копију
`/etc/ssl/certs/ca-certificates.crt`).

### wget

```sh
wget --ca-certificate=minica-ca.pem https://intranet.example.com/
echo "ca_certificate = /path/to/minica-ca.pem" >> ~/.wgetrc
```

### Python

`urllib`, `http.client` и `ssl` модул користе подразумеване путање OpenSSL-а,
тј. системско складиште, и поштују `SSL_CERT_FILE` / `SSL_CERT_DIR`. Библиотека
`requests` (и све што је на њој засновано, укључујући `pip`) уместо тога користи
пакет `certifi`:

```sh
export REQUESTS_CA_BUNDLE=/path/to/minica-ca.pem   # requests; replaces the bundle
export SSL_CERT_FILE=/path/to/minica-ca.pem        # ssl / urllib / httpx
pip config set global.cert /path/to/minica-ca.pem  # pip
```

Да бисте задржали и јавне CA-ове, додајте MiniCA PEM на копију certifi пакета
(`python -m certifi` исписује његову путању) и усмерите променљиве на ту
копију. `pip install pip-system-certs` или `truststore` чини да requests
уместо тога користи складиште оперативног система.

### Java / JVM (Kafka, Elasticsearch, Jenkins, ...)

Преузети CA truststore је готов за употребу PKCS#12 truststore (лозинка
`changeit`, CA је сачуван као `trustedCertEntry`):

```sh
curl -fsSLo minica-truststore.p12 https://ca.example.com/minica/download/ca/<ca-id>/truststore
java -Djavax.net.ssl.trustStore=minica-truststore.p12 \
     -Djavax.net.ssl.trustStorePassword=changeit \
     -Djavax.net.ssl.trustStoreType=PKCS12 -jar app.jar
```

Тај truststore садржи *само* MiniCA CA. Да бисте CA уместо тога додали у
подразумевано складиште JDK-а (да јавни CA-ови наставе да раде):

```sh
keytool -importcert -trustcacerts -noprompt -alias minica \
  -file minica-ca.pem -cacerts -storepass changeit
```

Kafka клијенти узимају `ssl.truststore.location=minica-truststore.p12`,
`ssl.truststore.password=changeit`, `ssl.truststore.type=PKCS12`.

### Go

Go користи системско складиште (`crypto/x509` чита `/etc/ssl/certs` на Linux-у) и
поштује `SSL_CERT_FILE` / `SSL_CERT_DIR`. Да додате CA из кода:

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

Ово *додаје* CA-овима које Node већ садржи. `--use-openssl-ca` чини да Node
уместо тога користи системско складиште.

### yt-dlp

yt-dlp је Python програм и прати Python правила: ако је `certifi`
инсталиран (уобичајен случај) користи certifi пакет, у супротном
подразумевано складиште OpenSSL-а. Или инсталирајте CA у системско складиште и уклоните /
заобиђите certifi, или усмерите HTTP стек yt-dlp-а на пакет који садржи оба:

```sh
cat "$(python3 -m certifi)" minica-ca.pem > ~/.config/yt-dlp/ca-bundle.pem
SSL_CERT_FILE=~/.config/yt-dlp/ca-bundle.pem REQUESTS_CA_BUNDLE=~/.config/yt-dlp/ca-bundle.pem yt-dlp https://media.intranet.example.com/...
```

Избегавајте `--no-check-certificates`; он потпуно искључује проверу.

## Сервери и сервиси

### Nginx

Лако је помешати три различите ствари:

- **Serving MiniCA сертификата.** Преузмите *Bundle* (zip) сертификата —
  `cert.pem`, `cert.key` и `ca.pem` — и користите
  ```nginx
  ssl_certificate     /etc/nginx/tls/cert.pem;    # or cat cert.pem ca.pem > fullchain.pem
  ssl_certificate_key /etc/nginx/tls/cert.key;
  ```
  Клијентима је тада потребан инсталиран CA како је описано на овој страници.
- **Nginx као TLS клијент** (проксирање ка upstream-у који представља
  MiniCA сертификат):
  ```nginx
  proxy_ssl_verify on;
  proxy_ssl_trusted_certificate /etc/nginx/tls/minica-ca.pem;
  proxy_ssl_name upstream.example.com;
  ```
- **Клијентски сертификати (mTLS) које издаје MiniCA:**
  ```nginx
  ssl_client_certificate /etc/nginx/tls/minica-ca.pem;
  ssl_verify_client on;
  ssl_crl /etc/nginx/tls/minica.crl.pem;   # optional: openssl crl -inform DER -in <crl> -out minica.crl.pem
  ```
  CRL се налази на `https://ca.example.com/minica/crl/<ca-id>` (DER).

### Docker

За **слику**, додајте CA приликом изградње да га виде сви алати у слици:

```dockerfile
# Debian/Ubuntu based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN update-ca-certificates
# Alpine based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN apk add --no-cache ca-certificates && update-ca-certificates
```

За **контејнер који не можете поново изградити**, монтирајте пакет који већ садржи
CA (нпр. `/etc/ssl/certs/ca-certificates.crt` са домаћина након инсталације
CA-а на домаћину) преко пакета из слике, или усмерите алате унутра на њега
преко горе наведених променљивих окружења:

```yaml
    environment:
      SSL_CERT_FILE:        /etc/ssl/certs/ca-certificates.crt   # OpenSSL, Python ssl, Go, Ruby
      REQUESTS_CA_BUNDLE:   /etc/ssl/certs/ca-certificates.crt   # Python requests
      CURL_CA_BUNDLE:       /etc/ssl/certs/ca-certificates.crt   # curl
      NODE_EXTRA_CA_CERTS:  /etc/ssl/certs/ca-certificates.crt   # Node.js
    volumes:
      - /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro
```

Слике засноване на дистрибуцијама које држе пакет на другом месту
(породица RHEL: `/etc/pki/tls/certs/ca-bundle.crt`) уместо тога захтевају ту путању.

Docker *daemon* верује CA-у приватног регистра из
`/etc/docker/certs.d/<registry:port>/ca.crt`, независно од системског складишта.

### LLDAP

LLDAP је сервер: дајте му сертификат који издаје MiniCA за његов LDAPS
слушалац (преузмите пакет сертификата; кључ је `cert.key`):

```toml
# lldap_config.toml
[ldaps_options]
enabled = true
port = 6360
cert_file = "/data/tls/cert.pem"
key_file = "/data/tls/cert.key"
```

или `LLDAP_LDAPS_OPTIONS__ENABLED=true`, `LLDAP_LDAPS_OPTIONS__CERT_FILE=...`,
`LLDAP_LDAPS_OPTIONS__KEY_FILE=...` у окружењу. Сваком LDAP клијенту
(Authelia, Nextcloud, Jellyfin, ...) тада је потребан MiniCA CA у сопственом
складишту поверења, према горњим рецептима за платформу или језик на којем ради.

## Објављивање MiniCA преко Nginx-а

Уз сопствену пријаву MiniCA-е довољан је један префикс. MiniCA сама штити своје приватне странице, а овај водич остаје јаван на `/minica/how-to-use`:

```nginx
location /minica/ {
    proxy_pass http://minica:9988;
    include /etc/nginx/snippets/proxy.conf;
}
```

Уз SSO (Authelia, oauth2-proxy, ...) префикс је заштићен, па јавним страницама треба једно сопствено правило. Држите заглавља идентитета очишћеним на том правилу, јер им MiniCA верује када долазе од проксија:

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

## Провера да ли ради

```sh
openssl s_client -connect intranet.example.com:443 -servername intranet.example.com </dev/null 2>/dev/null | grep "Verify return code"
curl -v https://intranet.example.com/ 2>&1 | grep -E "SSL certificate verify|issuer"
```

`Verify return code: 0 (ok)` значи да је клијент пронашао CA и поверовао му.
