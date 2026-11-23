<!-- source-sha256: 51e546526752332fcfc280e7dff9c74d662f180be9dc12f325b1f7754935dbb2 -->
# Доверяване на удостоверяващ орган на MiniCA

Сертификатите, издадени от MiniCA, се приемат от клиента само след като този
клиент се довери на издаващия CA. Тази страница събира рецептите за
най-често срещаните платформи и инструменти. Всичко започва от двете публични
изтегляния, които има всеки CA (не е нужен вход):

| Изтегляне | URL | За какво се използва |
| --- | --- | --- |
| Сертификат на CA (PEM) | `https://ca.example.com/minica/<ca-id>/download` | всичко освен Java |
| Хранилище за доверие на CA (PKCS#12, парола `changeit`) | `https://ca.example.com/minica/download/ca/<ca-id>/truststore` | Java / JVM приложения |

И двете са свързани и от публичния индекс на CA на `https://ca.example.com/minica/`
и от страницата на CA. Файлът е наименуван по общото име на CA, напр.
`Homelab_CA.pem`; примерите по-долу го наричат `minica-ca.pem` / `minica-ca.crt`.

```sh
curl -fsSLo minica-ca.pem https://ca.example.com/minica/<ca-id>/download
openssl x509 -in minica-ca.pem -noout -subject -dates -fingerprint -sha256   # check what you got
```

На клиентите се инсталира единствено **сертификатът на CA** — никога частен
ключ. Ако CA е междинен, инсталирайте вместо него (или заедно с него) неговия корен.

## Операционни системи

### Debian / Ubuntu

```sh
sudo cp minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt   # must end in .crt, PEM content
sudo update-ca-certificates
```

Това добавя CA към `/etc/ssl/certs/ca-certificates.crt`, който се използва от curl, wget,
Python, Go, Node (с `NODE_EXTRA_CA_CERTS` или `--use-openssl-ca`), apt и
повечето други програми в системата. `/usr/local/share/ca-certificates/`
е правилното място за локални добавки; `/usr/share/ca-certificates/` принадлежи
на пакета на дистрибуцията.

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

(Първо изпълнете `apk add ca-certificates`, ако `update-ca-certificates` липсва.)

### Arch Linux

```sh
sudo trust anchor --store minica-ca.pem
```

### macOS

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain minica-ca.pem
```

Или щракнете двукратно върху файла, добавете го към ключодържателя *System* в Keychain Access,
отворете го и задайте *When using this certificate* на *Always Trust*. Safari и
Chrome използват ключодържателя; Firefox изисква допълнителната стъпка по-долу.

### Windows

Като администратор (PowerShell):

```powershell
Import-Certificate -FilePath .\minica-ca.pem -CertStoreLocation Cert:\LocalMachine\Root
```

или `certutil -addstore -f Root minica-ca.pem`, или щракнете двукратно → *Install
Certificate* → *Local Machine* → *Place all certificates in the following
store* → *Trusted Root Certification Authorities*. Edge, Chrome и
.NET/PowerShell използват това хранилище; Firefox изисква допълнителната стъпка по-долу.

### Android

Android инсталира само DER или PEM файлове с име, завършващо на `.crt`/`.cer`:

```sh
openssl x509 -in minica-ca.pem -outform DER -out minica-ca.crt
```

Копирайте го на телефона, после *Settings → Security → Encryption & credentials →
Install a certificate → CA certificate*. Android 11+ предупреждава, че
сертификатът трябва да се инсталира от Settings; това е пътят по-горе.
Chrome и повечето приложения тогава му се доверяват, но приложенията, които закачат сертификати (pinning) или носят
собствено хранилище за доверие (и някои, които използват собствен мрежов стек), не му се доверяват.

### iOS / iPadOS

Отворете `.pem` на устройството (AirDrop, Mail, Files) → *Settings → Profile
Downloaded → Install*, после го разрешете в *Settings → General → About →
Certificate Trust Settings*.

## Браузъри

Chrome, Edge и Safari използват хранилището на операционната система, така че стъпките по-горе
са достатъчни. **Firefox** поддържа собствено хранилище, освен ако не е зададено друго:

- Preferences → Privacy & Security → Certificates → *View Certificates* →
  *Authorities* → *Import* → отметнете *Trust this CA to identify websites*; или
- задайте `security.enterprise_roots.enabled` на `true` в `about:config`, за да накарате
  Firefox да използва системното хранилище на Windows / macOS; или
- на Linux импортирайте в NSS базата данни на профила:
  `certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.mozilla/firefox/<profile>` (`certutil` от `libnss3-tools` / `nss-tools`).

Chromium на Linux също има NSS хранилище за CA, инсталирани от потребителя:
`certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.pki/nssdb`.

## Инструменти от командния ред и езици

### curl

```sh
curl --cacert minica-ca.pem https://intranet.example.com/
export CURL_CA_BUNDLE=/path/to/minica-ca.pem     # for a shell session
```

След инсталиране на CA в системното хранилище (по-горе) не е нужна опция.
`CURL_CA_BUNDLE` *замества* пакета, затова го насочете към файл, който съдържа
и публичните CA, ако ви трябват и двата (напр. добавете PEM на MiniCA към копие
на `/etc/ssl/certs/ca-certificates.crt`).

### wget

```sh
wget --ca-certificate=minica-ca.pem https://intranet.example.com/
echo "ca_certificate = /path/to/minica-ca.pem" >> ~/.wgetrc
```

### Python

`urllib`, `http.client` и модулът `ssl` използват пътищата по подразбиране на OpenSSL,
т.е. системното хранилище, и зачитат `SSL_CERT_FILE` / `SSL_CERT_DIR`.
Библиотеката `requests` (и всичко, изградено върху нея, включително `pip`) използва
пакета `certifi`:

```sh
export REQUESTS_CA_BUNDLE=/path/to/minica-ca.pem   # requests; replaces the bundle
export SSL_CERT_FILE=/path/to/minica-ca.pem        # ssl / urllib / httpx
pip config set global.cert /path/to/minica-ca.pem  # pip
```

За да запазите и публичните CA, добавете PEM на MiniCA към копие на пакета на certifi
(`python -m certifi` отпечатва пътя му) и насочете променливите към
копието. `pip install pip-system-certs` или `truststore` кара requests да използва
хранилището на операционната система.

### Java / JVM (Kafka, Elasticsearch, Jenkins, ...)

Изтеглянето на хранилището за доверие на CA е готово за употреба PKCS#12 хранилище (парола
`changeit`, CA е записан като `trustedCertEntry`):

```sh
curl -fsSLo minica-truststore.p12 https://ca.example.com/minica/download/ca/<ca-id>/truststore
java -Djavax.net.ssl.trustStore=minica-truststore.p12 \
     -Djavax.net.ssl.trustStorePassword=changeit \
     -Djavax.net.ssl.trustStoreType=PKCS12 -jar app.jar
```

Това хранилище съдържа *само* CA на MiniCA. За да добавите CA към
хранилището по подразбиране на JDK (така че публичните CA да продължат да работят):

```sh
keytool -importcert -trustcacerts -noprompt -alias minica \
  -file minica-ca.pem -cacerts -storepass changeit
```

Клиентите на Kafka приемат `ssl.truststore.location=minica-truststore.p12`,
`ssl.truststore.password=changeit`, `ssl.truststore.type=PKCS12`.

### Go

Go използва системното хранилище (`crypto/x509` чете `/etc/ssl/certs` на Linux) и
зачита `SSL_CERT_FILE` / `SSL_CERT_DIR`. За да добавите CA от код:

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

Това *добавя* към вградените CA на Node. `--use-openssl-ca` кара Node да използва
системното хранилище вместо тях.

### yt-dlp

yt-dlp е програма на Python и следва правилата на Python: ако `certifi` е
инсталиран (обичайният случай), използва пакета на certifi, иначе
хранилището по подразбиране на OpenSSL. Или инсталирайте CA в системното хранилище и премахнете /
заобиколете certifi, или насочете HTTP стека на yt-dlp към пакет, който съдържа и двата:

```sh
cat "$(python3 -m certifi)" minica-ca.pem > ~/.config/yt-dlp/ca-bundle.pem
SSL_CERT_FILE=~/.config/yt-dlp/ca-bundle.pem REQUESTS_CA_BUNDLE=~/.config/yt-dlp/ca-bundle.pem yt-dlp https://media.intranet.example.com/...
```

Избягвайте `--no-check-certificates`; то изключва проверката напълно.

## Сървъри и услуги

### Nginx

Три различни неща лесно се бъркат:

- **Предоставяне на сертификат, издаден от MiniCA.** Изтеглете
  *Bundle* (zip) на сертификата — `cert.pem`, `cert.key` и `ca.pem` — и използвайте
  ```nginx
  ssl_certificate     /etc/nginx/tls/cert.pem;    # or cat cert.pem ca.pem > fullchain.pem
  ssl_certificate_key /etc/nginx/tls/cert.key;
  ```
  Тогава клиентите се нуждаят от инсталиран CA, както е описано на тази страница.
- **Nginx като TLS клиент** (проксиране към upstream, който представя
  сертификат на MiniCA):
  ```nginx
  proxy_ssl_verify on;
  proxy_ssl_trusted_certificate /etc/nginx/tls/minica-ca.pem;
  proxy_ssl_name upstream.example.com;
  ```
- **Клиентски сертификати (mTLS), издадени от MiniCA:**
  ```nginx
  ssl_client_certificate /etc/nginx/tls/minica-ca.pem;
  ssl_verify_client on;
  ssl_crl /etc/nginx/tls/minica.crl.pem;   # optional: openssl crl -inform DER -in <crl> -out minica.crl.pem
  ```
  CRL се намира на `https://ca.example.com/minica/crl/<ca-id>` (DER).

### Docker

За **образ** добавете CA по време на изграждането, така че всеки инструмент в образа да го вижда:

```dockerfile
# Debian/Ubuntu based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN update-ca-certificates
# Alpine based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN apk add --no-cache ca-certificates && update-ca-certificates
```

За **контейнер, който не можете да изградите наново**, монтирайте пакет, който вече съдържа
CA (напр. `/etc/ssl/certs/ca-certificates.crt` на хоста след инсталиране на
CA на хоста) върху пакета на образа или насочете инструментите вътре към него
чрез променливите на средата по-горе:

```yaml
    environment:
      SSL_CERT_FILE:        /etc/ssl/certs/ca-certificates.crt   # OpenSSL, Python ssl, Go, Ruby
      REQUESTS_CA_BUNDLE:   /etc/ssl/certs/ca-certificates.crt   # Python requests
      CURL_CA_BUNDLE:       /etc/ssl/certs/ca-certificates.crt   # curl
      NODE_EXTRA_CA_CERTS:  /etc/ssl/certs/ca-certificates.crt   # Node.js
    volumes:
      - /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro
```

Образите, базирани на дистрибуции, които държат пакета другаде
(семейството на RHEL: `/etc/pki/tls/certs/ca-bundle.crt`), се нуждаят от този път.

*Демонът* на Docker се доверява на CA на частен регистър от
`/etc/docker/certs.d/<registry:port>/ca.crt`, независимо от системното хранилище.

### LLDAP

LLDAP е сървър: дайте му сертификат, издаден от MiniCA, за неговия LDAPS
слушател (изтеглете пакета на сертификата; ключът е `cert.key`):

```toml
# lldap_config.toml
[ldaps_options]
enabled = true
port = 6360
cert_file = "/data/tls/cert.pem"
key_file = "/data/tls/cert.key"
```

или `LLDAP_LDAPS_OPTIONS__ENABLED=true`, `LLDAP_LDAPS_OPTIONS__CERT_FILE=...`,
`LLDAP_LDAPS_OPTIONS__KEY_FILE=...` в средата. Всеки LDAP клиент
(Authelia, Nextcloud, Jellyfin, ...) тогава се нуждае от CA на MiniCA в собственото си
хранилище за доверие, според рецептите по-горе за платформата или езика, на който работи.

## Публикуване на MiniCA през Nginx

С вграденото влизане на MiniCA един префикс е достатъчен. MiniCA сама защитава частните си страници, а това ръководство остава публично на `/minica/how-to-use`:

```nginx
location /minica/ {
    proxy_pass http://minica:9988;
    include /etc/nginx/snippets/proxy.conf;
}
```

При SSO (Authelia, oauth2-proxy, ...) префиксът е защитен, така че публичните страници се нуждаят от отделно правило. Дръжте заглавките за самоличност изчистени в това правило, защото MiniCA им вярва, когато идват от проксито:

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

## Проверка дали работи

```sh
openssl s_client -connect intranet.example.com:443 -servername intranet.example.com </dev/null 2>/dev/null | grep "Verify return code"
curl -v https://intranet.example.com/ 2>&1 | grep -E "SSL certificate verify|issuer"
```

`Verify return code: 0 (ok)` означава, че клиентът е намерил CA и му се доверява.
