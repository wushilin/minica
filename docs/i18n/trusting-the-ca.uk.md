<!-- source-sha256: 51e546526752332fcfc280e7dff9c74d662f180be9dc12f325b1f7754935dbb2 -->
# Довіра до центру сертифікації MiniCA

Сертифікати, видані MiniCA, приймаються клієнтом лише тоді, коли цей клієнт
довіряє центру сертифікації, що їх видав. Ця сторінка містить рецепти для
поширених платформ та інструментів. Усе починається з двох публічних
завантажень, які має кожен ЦС (вхід не потрібен):

| Завантаження | URL | Для чого |
| --- | --- | --- |
| Сертифікат ЦС (PEM) | `https://ca.example.com/minica/<ca-id>/download` | усе, крім Java |
| Сховище довіри ЦС (PKCS#12, пароль `changeit`) | `https://ca.example.com/minica/download/ca/<ca-id>/truststore` | застосунки Java / JVM |

Обидва також доступні за посиланнями в публічному індексі ЦС за адресою `https://ca.example.com/minica/`
і на сторінці ЦС. Файл названо за загальним іменем ЦС, наприклад
`Homelab_CA.pem`; у прикладах нижче він називається `minica-ca.pem` / `minica-ca.crt`.

```sh
curl -fsSLo minica-ca.pem https://ca.example.com/minica/<ca-id>/download
openssl x509 -in minica-ca.pem -noout -subject -dates -fingerprint -sha256   # check what you got
```

На клієнтах установлюється лише **сертифікат ЦС** — ніколи приватний
ключ. Якщо ЦС є проміжним, установіть натомість його кореневий сертифікат (або також його).

## Операційні системи

### Debian / Ubuntu

```sh
sudo cp minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt   # must end in .crt, PEM content
sudo update-ca-certificates
```

Це додає ЦС до `/etc/ssl/certs/ca-certificates.crt`, яким користуються curl, wget,
Python, Go, Node (з `NODE_EXTRA_CA_CERTS` або `--use-openssl-ca`), apt і
більшість інших програм у системі. `/usr/local/share/ca-certificates/`
— це правильне місце для локальних доповнень; `/usr/share/ca-certificates/` належить
пакету дистрибутива.

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

(Спершу виконайте `apk add ca-certificates`, якщо `update-ca-certificates` бракує.)

### Arch Linux

```sh
sudo trust anchor --store minica-ca.pem
```

### macOS

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain minica-ca.pem
```

Або двічі клацніть файл, додайте його до зв'язки ключів *System* у «Доступі до зв'язки ключів»,
відкрийте його й установіть *При використанні цього сертифіката* на *Завжди довіряти*. Safari і
Chrome використовують зв'язку ключів; Firefox потребує додаткового кроку нижче.

### Windows

Від імені адміністратора (PowerShell):

```powershell
Import-Certificate -FilePath .\minica-ca.pem -CertStoreLocation Cert:\LocalMachine\Root
```

або `certutil -addstore -f Root minica-ca.pem`, або двічі клацніть → *Установити
сертифікат* → *Локальний комп'ютер* → *Помістити всі сертифікати в таке
сховище* → *Довірені кореневі центри сертифікації*. Edge, Chrome і
.NET/PowerShell використовують це сховище; Firefox потребує додаткового кроку нижче.

### Android

Android встановлює лише файли DER або PEM з іменем `.crt`/`.cer`:

```sh
openssl x509 -in minica-ca.pem -outform DER -out minica-ca.crt
```

Скопіюйте його на телефон, потім *Налаштування → Безпека → Шифрування та облікові дані →
Установити сертифікат → Сертифікат ЦС*. Android 11+ попереджає, що
сертифікат потрібно встановлювати з налаштувань; це і є шлях вище.
Chrome і більшість застосунків після цього довіряють йому, але застосунки, що закріплюють сертифікати або постачають
власне сховище довіри (і деякі, що використовують власний мережевий стек), не довіряватимуть.

### iOS / iPadOS

Відкрийте `.pem` на пристрої (AirDrop, Пошта, Файли) → *Налаштування → Профіль
завантажено → Установити*, потім увімкніть його в *Налаштування → Загальні → Про пристрій →
Налаштування довіри сертифікатів*.

## Браузери

Chrome, Edge і Safari використовують сховище операційної системи, тож наведених вище кроків
достатньо. **Firefox** тримає власне сховище, якщо не вказано інше:

- Параметри → Приватність і безпека → Сертифікати → *Переглянути сертифікати* →
  *Центри сертифікації* → *Імпортувати* → позначте *Довіряти цьому ЦС для ідентифікації вебсайтів*; або
- установіть `security.enterprise_roots.enabled` у `true` в `about:config`, щоб
  Firefox використовував системне сховище Windows / macOS; або
- у Linux імпортуйте до бази NSS профілю:
  `certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.mozilla/firefox/<profile>` (`certutil` з `libnss3-tools` / `nss-tools`).

Chromium у Linux також має сховище NSS для встановлених користувачем ЦС:
`certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.pki/nssdb`.

## Інструменти командного рядка та мови програмування

### curl

```sh
curl --cacert minica-ca.pem https://intranet.example.com/
export CURL_CA_BUNDLE=/path/to/minica-ca.pem     # for a shell session
```

Після встановлення ЦС до системного сховища (вище) жодна опція не потрібна.
`CURL_CA_BUNDLE` *замінює* набір, тож вкажіть файл, який також
містить публічні ЦС, якщо потрібні обидва (наприклад, додайте PEM MiniCA до копії
`/etc/ssl/certs/ca-certificates.crt`).

### wget

```sh
wget --ca-certificate=minica-ca.pem https://intranet.example.com/
echo "ca_certificate = /path/to/minica-ca.pem" >> ~/.wgetrc
```

### Python

`urllib`, `http.client` і модуль `ssl` використовують типові шляхи OpenSSL,
тобто системне сховище, і враховують `SSL_CERT_FILE` / `SSL_CERT_DIR`. Бібліотека
`requests` (і все, що на ній побудовано, зокрема `pip`) натомість використовує
набір `certifi`:

```sh
export REQUESTS_CA_BUNDLE=/path/to/minica-ca.pem   # requests; replaces the bundle
export SSL_CERT_FILE=/path/to/minica-ca.pem        # ssl / urllib / httpx
pip config set global.cert /path/to/minica-ca.pem  # pip
```

Щоб зберегти також публічні ЦС, додайте PEM MiniCA до копії набору certifi
(`python -m certifi` виводить його шлях) і вкажіть змінним цю
копію. `pip install pip-system-certs` або `truststore` змушує requests використовувати
натомість сховище операційної системи.

### Java / JVM (Kafka, Elasticsearch, Jenkins, ...)

Завантажене сховище довіри ЦС — це готове до використання сховище довіри PKCS#12 (пароль
`changeit`, ЦС збережено як `trustedCertEntry`):

```sh
curl -fsSLo minica-truststore.p12 https://ca.example.com/minica/download/ca/<ca-id>/truststore
java -Djavax.net.ssl.trustStore=minica-truststore.p12 \
     -Djavax.net.ssl.trustStorePassword=changeit \
     -Djavax.net.ssl.trustStoreType=PKCS12 -jar app.jar
```

Це сховище довіри містить *лише* ЦС MiniCA. Щоб натомість додати ЦС до
типового сховища JDK (щоб публічні ЦС і далі працювали):

```sh
keytool -importcert -trustcacerts -noprompt -alias minica \
  -file minica-ca.pem -cacerts -storepass changeit
```

Клієнти Kafka приймають `ssl.truststore.location=minica-truststore.p12`,
`ssl.truststore.password=changeit`, `ssl.truststore.type=PKCS12`.

### Go

Go використовує системне сховище (`crypto/x509` читає `/etc/ssl/certs` у Linux) і
враховує `SSL_CERT_FILE` / `SSL_CERT_DIR`. Щоб додати ЦС із коду:

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

Це *додає* до вбудованих ЦС Node. `--use-openssl-ca` змушує Node використовувати
натомість системне сховище.

### yt-dlp

yt-dlp — це програма на Python, тож діють правила Python: якщо встановлено `certifi`
(звичайний випадок), він використовує набір certifi, інакше — типове сховище
OpenSSL. Або встановіть ЦС до системного сховища й вимкніть /
обійдіть certifi, або вкажіть HTTP-стеку yt-dlp набір, що містить обидва:

```sh
cat "$(python3 -m certifi)" minica-ca.pem > ~/.config/yt-dlp/ca-bundle.pem
SSL_CERT_FILE=~/.config/yt-dlp/ca-bundle.pem REQUESTS_CA_BUNDLE=~/.config/yt-dlp/ca-bundle.pem yt-dlp https://media.intranet.example.com/...
```

Уникайте `--no-check-certificates`; воно повністю вимикає перевірку.

## Сервери та сервіси

### Nginx

Легко сплутати три різні речі:

- **Надання сертифіката, виданого MiniCA.** Завантажте *пакет* (zip) сертифіката
  — `cert.pem`, `cert.key` і `ca.pem` — і використайте
  ```nginx
  ssl_certificate     /etc/nginx/tls/cert.pem;    # or cat cert.pem ca.pem > fullchain.pem
  ssl_certificate_key /etc/nginx/tls/cert.key;
  ```
  Тоді клієнтам потрібен установлений ЦС, як описано на цій сторінці.
- **Nginx як TLS-клієнт** (проксування до вихідного сервера, що пред'являє
  сертифікат MiniCA):
  ```nginx
  proxy_ssl_verify on;
  proxy_ssl_trusted_certificate /etc/nginx/tls/minica-ca.pem;
  proxy_ssl_name upstream.example.com;
  ```
- **Клієнтські сертифікати (mTLS), видані MiniCA:**
  ```nginx
  ssl_client_certificate /etc/nginx/tls/minica-ca.pem;
  ssl_verify_client on;
  ssl_crl /etc/nginx/tls/minica.crl.pem;   # optional: openssl crl -inform DER -in <crl> -out minica.crl.pem
  ```
  CRL розташований за адресою `https://ca.example.com/minica/crl/<ca-id>` (DER).

### Docker

Для **образу** додайте ЦС під час збирання, щоб його бачив кожен інструмент в образі:

```dockerfile
# Debian/Ubuntu based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN update-ca-certificates
# Alpine based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN apk add --no-cache ca-certificates && update-ca-certificates
```

Для **контейнера, який не можна перезібрати**, змонтуйте набір, що вже містить
ЦС (наприклад, `/etc/ssl/certs/ca-certificates.crt` хоста після встановлення
ЦС на хості), поверх набору образу або вкажіть інструментам усередині його
через змінні середовища вище:

```yaml
    environment:
      SSL_CERT_FILE:        /etc/ssl/certs/ca-certificates.crt   # OpenSSL, Python ssl, Go, Ruby
      REQUESTS_CA_BUNDLE:   /etc/ssl/certs/ca-certificates.crt   # Python requests
      CURL_CA_BUNDLE:       /etc/ssl/certs/ca-certificates.crt   # curl
      NODE_EXTRA_CA_CERTS:  /etc/ssl/certs/ca-certificates.crt   # Node.js
    volumes:
      - /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro
```

Образам на основі дистрибутивів, що тримають набір деінде
(родина RHEL: `/etc/pki/tls/certs/ca-bundle.crt`), потрібен натомість той шлях.

*Демон* Docker довіряє ЦС приватного реєстру з
`/etc/docker/certs.d/<registry:port>/ca.crt`, незалежно від системного сховища.

### LLDAP

LLDAP — це сервер: надайте йому сертифікат, виданий MiniCA, для його LDAPS-
слухача (завантажте пакет сертифіката; ключ — `cert.key`):

```toml
# lldap_config.toml
[ldaps_options]
enabled = true
port = 6360
cert_file = "/data/tls/cert.pem"
key_file = "/data/tls/cert.key"
```

або `LLDAP_LDAPS_OPTIONS__ENABLED=true`, `LLDAP_LDAPS_OPTIONS__CERT_FILE=...`,
`LLDAP_LDAPS_OPTIONS__KEY_FILE=...` у середовищі. Кожному клієнту LDAP
(Authelia, Nextcloud, Jellyfin, ...) тоді потрібен ЦС MiniCA у власному
сховищі довіри, за рецептами вище для платформи чи мови, на якій він працює.

## Публікація MiniCA через Nginx

З власним входом MiniCA достатньо одного префікса. MiniCA сама захищає свої приватні сторінки, а цей посібник залишається публічним за адресою `/minica/how-to-use`:

```nginx
location /minica/ {
    proxy_pass http://minica:9988;
    include /etc/nginx/snippets/proxy.conf;
}
```

З SSO (Authelia, oauth2-proxy, ...) префікс захищений, тож публічним сторінкам потрібне окреме правило. Залишайте заголовки ідентичності очищеними в цьому правилі, бо MiniCA довіряє їм, коли вони надходять від проксі:

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

## Перевірка роботи

```sh
openssl s_client -connect intranet.example.com:443 -servername intranet.example.com </dev/null 2>/dev/null | grep "Verify return code"
curl -v https://intranet.example.com/ 2>&1 | grep -E "SSL certificate verify|issuer"
```

`Verify return code: 0 (ok)` означає, що клієнт знайшов ЦС і довіряє йому.
