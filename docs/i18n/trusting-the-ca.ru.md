<!-- source-sha256: 51e546526752332fcfc280e7dff9c74d662f180be9dc12f325b1f7754935dbb2 -->
# Доверие к удостоверяющему центру MiniCA

Сертификаты, выпущенные MiniCA, принимаются клиентом только после того, как
этот клиент начнёт доверять выпустившему их УЦ. На этой странице собраны
рецепты для распространённых платформ и инструментов. Всё начинается с двух
публичных загрузок, которые есть у каждого УЦ (вход в систему не нужен):

| Загрузка | URL | Для чего использовать |
| --- | --- | --- |
| Сертификат УЦ (PEM) | `https://ca.example.com/minica/<ca-id>/download` | для всего, кроме Java |
| Хранилище доверенных сертификатов УЦ (PKCS#12, пароль `changeit`) | `https://ca.example.com/minica/download/ca/<ca-id>/truststore` | приложения Java / JVM |

Обе загрузки также доступны по ссылкам из публичного индекса УЦ по адресу `https://ca.example.com/minica/`
и со страницы УЦ. Файл называется по общему имени (common name) УЦ, например
`Homelab_CA.pem`; в примерах ниже он называется `minica-ca.pem` / `minica-ca.crt`.

```sh
curl -fsSLo minica-ca.pem https://ca.example.com/minica/<ca-id>/download
openssl x509 -in minica-ca.pem -noout -subject -dates -fingerprint -sha256   # check what you got
```

На клиентах устанавливается только **сертификат УЦ** — ни в коем случае не
закрытый ключ. Если УЦ является промежуточным, установите вместо него (или
вместе с ним) корневой сертификат.

## Операционные системы

### Debian / Ubuntu

```sh
sudo cp minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt   # must end in .crt, PEM content
sudo update-ca-certificates
```

Так УЦ добавляется в `/etc/ssl/certs/ca-certificates.crt` — этим файлом
пользуются curl, wget, Python, Go, Node (с `NODE_EXTRA_CA_CERTS` или `--use-openssl-ca`), apt и
большинство других программ в системе. `/usr/local/share/ca-certificates/` —
правильное место для локальных дополнений; `/usr/share/ca-certificates/`
принадлежит пакету дистрибутива.

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

(Сначала выполните `apk add ca-certificates`, если `update-ca-certificates` отсутствует.)

### Arch Linux

```sh
sudo trust anchor --store minica-ca.pem
```

### macOS

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain minica-ca.pem
```

Или дважды щёлкните файл, добавьте его в связку ключей *System* в программе «Связка ключей»,
откройте его и установите для параметра *When using this certificate* значение *Always Trust*. Safari и
Chrome используют связку ключей; для Firefox нужен дополнительный шаг, описанный ниже.

### Windows

От имени администратора (PowerShell):

```powershell
Import-Certificate -FilePath .\minica-ca.pem -CertStoreLocation Cert:\LocalMachine\Root
```

или `certutil -addstore -f Root minica-ca.pem`, или дважды щёлкните файл → *Install
Certificate* → *Local Machine* → *Place all certificates in the following
store* → *Trusted Root Certification Authorities*. Edge, Chrome и
.NET/PowerShell используют это хранилище; для Firefox нужен дополнительный шаг, описанный ниже.

### Android

Android устанавливает только файлы DER или PEM с именем `.crt`/`.cer`:

```sh
openssl x509 -in minica-ca.pem -outform DER -out minica-ca.crt
```

Скопируйте файл на телефон, затем выберите *Settings → Security → Encryption & credentials →
Install a certificate → CA certificate*. Android 11+ предупреждает, что
сертификат нужно устанавливать через «Настройки»; именно этот путь описан выше.
После этого Chrome и большинство приложений будут ему доверять, но приложения, которые закрепляют сертификаты (pinning) или поставляются
со своим хранилищем доверия (а также некоторые, использующие собственный сетевой стек), доверять не будут.

### iOS / iPadOS

Откройте `.pem` на устройстве (AirDrop, Mail, Files) → *Settings → Profile
Downloaded → Install*, затем включите доверие в разделе *Settings → General → About →
Certificate Trust Settings*.

## Браузеры

Chrome, Edge и Safari используют хранилище операционной системы, поэтому
описанных выше шагов достаточно. **Firefox** ведёт собственное хранилище, если не указано иное:

- Preferences → Privacy & Security → Certificates → *View Certificates* →
  *Authorities* → *Import* → отметьте *Trust this CA to identify websites*; или
- установите `security.enterprise_roots.enabled` в значение `true` в `about:config`, чтобы
  Firefox использовал системное хранилище Windows / macOS; или
- в Linux импортируйте сертификат в базу NSS профиля:
  `certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.mozilla/firefox/<profile>` (`certutil` из `libnss3-tools` / `nss-tools`).

В Chromium под Linux также есть хранилище NSS для УЦ, установленных пользователем:
`certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.pki/nssdb`.

## Инструменты командной строки и языки программирования

### curl

```sh
curl --cacert minica-ca.pem https://intranet.example.com/
export CURL_CA_BUNDLE=/path/to/minica-ca.pem     # for a shell session
```

После установки УЦ в системное хранилище (см. выше) никакие параметры не нужны.
`CURL_CA_BUNDLE` *заменяет* набор сертификатов, поэтому укажите файл, который содержит
в том числе и публичные УЦ, если нужны оба набора (например, добавьте PEM MiniCA в копию
`/etc/ssl/certs/ca-certificates.crt`).

### wget

```sh
wget --ca-certificate=minica-ca.pem https://intranet.example.com/
echo "ca_certificate = /path/to/minica-ca.pem" >> ~/.wgetrc
```

### Python

`urllib`, `http.client` и модуль `ssl` используют пути OpenSSL по умолчанию,
то есть системное хранилище, и учитывают `SSL_CERT_FILE` / `SSL_CERT_DIR`. Библиотека
`requests` (и всё, что построено на ней, включая `pip`) вместо этого использует
набор `certifi`:

```sh
export REQUESTS_CA_BUNDLE=/path/to/minica-ca.pem   # requests; replaces the bundle
export SSL_CERT_FILE=/path/to/minica-ca.pem        # ssl / urllib / httpx
pip config set global.cert /path/to/minica-ca.pem  # pip
```

Чтобы сохранить и публичные УЦ, добавьте PEM MiniCA в копию набора certifi
(`python -m certifi` выводит путь к нему) и укажите в переменных путь к
копии. Команда `pip install pip-system-certs` или пакет `truststore` заставляет requests использовать
хранилище операционной системы.

### Java / JVM (Kafka, Elasticsearch, Jenkins, ...)

Загрузка хранилища доверенных сертификатов УЦ — это готовое к использованию хранилище PKCS#12 (пароль
`changeit`, УЦ хранится как `trustedCertEntry`):

```sh
curl -fsSLo minica-truststore.p12 https://ca.example.com/minica/download/ca/<ca-id>/truststore
java -Djavax.net.ssl.trustStore=minica-truststore.p12 \
     -Djavax.net.ssl.trustStorePassword=changeit \
     -Djavax.net.ssl.trustStoreType=PKCS12 -jar app.jar
```

Это хранилище содержит *только* УЦ MiniCA. Чтобы вместо этого добавить УЦ в
хранилище JDK по умолчанию (чтобы публичные УЦ продолжали работать):

```sh
keytool -importcert -trustcacerts -noprompt -alias minica \
  -file minica-ca.pem -cacerts -storepass changeit
```

Клиентам Kafka нужно задать `ssl.truststore.location=minica-truststore.p12`,
`ssl.truststore.password=changeit`, `ssl.truststore.type=PKCS12`.

### Go

Go использует системное хранилище (`crypto/x509` читает `/etc/ssl/certs` в Linux) и
учитывает `SSL_CERT_FILE` / `SSL_CERT_DIR`. Чтобы добавить УЦ из кода:

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

Это *дополняет* встроенные в Node УЦ. Параметр `--use-openssl-ca` заставляет Node использовать
системное хранилище.

### yt-dlp

yt-dlp — программа на Python, и к ней применимы правила Python: если установлен `certifi`
(обычный случай), используется его набор, иначе — хранилище OpenSSL
по умолчанию. Либо установите УЦ в системное хранилище и удалите /
обойдите certifi, либо направьте HTTP-стек yt-dlp на набор, содержащий оба набора:

```sh
cat "$(python3 -m certifi)" minica-ca.pem > ~/.config/yt-dlp/ca-bundle.pem
SSL_CERT_FILE=~/.config/yt-dlp/ca-bundle.pem REQUESTS_CA_BUNDLE=~/.config/yt-dlp/ca-bundle.pem yt-dlp https://media.intranet.example.com/...
```

Избегайте `--no-check-certificates`: он полностью отключает проверку.

## Серверы и службы

### Nginx

Здесь легко перепутать три разные вещи:

- **Выдача сертификата, выпущенного MiniCA.** Скачайте
  *Bundle* сертификата (zip) — `cert.pem`, `cert.key` и `ca.pem` — и используйте
  ```nginx
  ssl_certificate     /etc/nginx/tls/cert.pem;    # or cat cert.pem ca.pem > fullchain.pem
  ssl_certificate_key /etc/nginx/tls/cert.key;
  ```
  Затем на клиентах нужно установить УЦ, как описано на этой странице.
- **Nginx как TLS-клиент** (проксирование на вышестоящий сервер, который предъявляет
  сертификат MiniCA):
  ```nginx
  proxy_ssl_verify on;
  proxy_ssl_trusted_certificate /etc/nginx/tls/minica-ca.pem;
  proxy_ssl_name upstream.example.com;
  ```
- **Клиентские сертификаты (mTLS), выпущенные MiniCA:**
  ```nginx
  ssl_client_certificate /etc/nginx/tls/minica-ca.pem;
  ssl_verify_client on;
  ssl_crl /etc/nginx/tls/minica.crl.pem;   # optional: openssl crl -inform DER -in <crl> -out minica.crl.pem
  ```
  CRL находится по адресу `https://ca.example.com/minica/crl/<ca-id>` (DER).

### Docker

Для **образа** добавляйте УЦ во время сборки, чтобы его видели все инструменты в образе:

```dockerfile
# Debian/Ubuntu based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN update-ca-certificates
# Alpine based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN apk add --no-cache ca-certificates && update-ca-certificates
```

Для **контейнера, который нельзя пересобрать**, смонтируйте набор, уже содержащий
УЦ (например, `/etc/ssl/certs/ca-certificates.crt` хоста после установки
УЦ на хост), поверх набора образа или направьте инструменты внутри контейнера на него
через описанные выше переменные окружения:

```yaml
    environment:
      SSL_CERT_FILE:        /etc/ssl/certs/ca-certificates.crt   # OpenSSL, Python ssl, Go, Ruby
      REQUESTS_CA_BUNDLE:   /etc/ssl/certs/ca-certificates.crt   # Python requests
      CURL_CA_BUNDLE:       /etc/ssl/certs/ca-certificates.crt   # curl
      NODE_EXTRA_CA_CERTS:  /etc/ssl/certs/ca-certificates.crt   # Node.js
    volumes:
      - /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro
```

Образам на основе дистрибутивов, которые хранят набор сертификатов в другом месте
(семейство RHEL: `/etc/pki/tls/certs/ca-bundle.crt`), нужен именно этот путь.

*Демон* Docker доверяет УЦ частного реестра из
`/etc/docker/certs.d/<registry:port>/ca.crt` независимо от системного хранилища.

### LLDAP

LLDAP — это сервер: выдайте ему сертификат, выпущенный MiniCA, для прослушивателя
LDAPS (скачайте набор файлов сертификата; ключ — `cert.key`):

```toml
# lldap_config.toml
[ldaps_options]
enabled = true
port = 6360
cert_file = "/data/tls/cert.pem"
key_file = "/data/tls/cert.key"
```

или задайте в окружении `LLDAP_LDAPS_OPTIONS__ENABLED=true`, `LLDAP_LDAPS_OPTIONS__CERT_FILE=...`,
`LLDAP_LDAPS_OPTIONS__KEY_FILE=...`. Каждому LDAP-клиенту
(Authelia, Nextcloud, Jellyfin, ...) после этого нужен УЦ MiniCA в его собственном
хранилище доверия — по рецептам выше для платформы или языка, на котором он работает.

## Публикация MiniCA через Nginx

При использовании собственного входа MiniCA достаточно одного префикса. MiniCA сам защищает закрытые страницы, а это руководство остаётся общедоступным по адресу `/minica/how-to-use`:

```nginx
location /minica/ {
    proxy_pass http://minica:9988;
    include /etc/nginx/snippets/proxy.conf;
}
```

При использовании SSO (Authelia, oauth2-proxy и т. п.) префикс защищён, поэтому общедоступным страницам нужно отдельное правило. Очищайте в нём заголовки идентификации, поскольку MiniCA доверяет им, когда они приходят от прокси:

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

## Проверка работоспособности

```sh
openssl s_client -connect intranet.example.com:443 -servername intranet.example.com </dev/null 2>/dev/null | grep "Verify return code"
curl -v https://intranet.example.com/ 2>&1 | grep -E "SSL certificate verify|issuer"
```

`Verify return code: 0 (ok)` означает, что клиент нашёл УЦ и доверяет ему.
