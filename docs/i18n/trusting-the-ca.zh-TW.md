<!-- source-sha256: 51e546526752332fcfc280e7dff9c74d662f180be9dc12f325b1f7754935dbb2 -->
# 信任 MiniCA 憑證授權單位

只有在用戶端信任簽發憑證的 CA 之後，才會接受由 MiniCA 簽發的憑證。本頁整理了常見平台與工具的設定方式。所有步驟都從每個 CA 都提供的兩個公開下載項目開始（不需要登入）：

| 下載項目 | URL | 用途 |
| --- | --- | --- |
| CA 憑證（PEM） | `https://ca.example.com/minica/<ca-id>/download` | 除 Java 以外的所有情況 |
| CA 信任存放區（PKCS#12，密碼為 `changeit`） | `https://ca.example.com/minica/download/ca/<ca-id>/truststore` | Java / JVM 應用程式 |

這兩個檔案也可從公開的 CA 索引頁 `https://ca.example.com/minica/` 以及 CA 頁面取得連結。檔名以 CA 的通用名稱（Common Name）命名，例如 `Homelab_CA.pem`；以下範例將其稱為 `minica-ca.pem` / `minica-ca.crt`。

```sh
curl -fsSLo minica-ca.pem https://ca.example.com/minica/<ca-id>/download
openssl x509 -in minica-ca.pem -noout -subject -dates -fingerprint -sha256   # check what you got
```

用戶端只會安裝 **CA 憑證**，絕對不要安裝私密金鑰。如果該 CA 是中繼 CA，請改為安裝其根憑證（或一併安裝）。

## 作業系統

### Debian / Ubuntu

```sh
sudo cp minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt   # must end in .crt, PEM content
sudo update-ca-certificates
```

這會將 CA 加入 `/etc/ssl/certs/ca-certificates.crt`，系統上的 curl、wget、Python、Go、Node（搭配 `NODE_EXTRA_CA_CERTS` 或 `--use-openssl-ca`）、apt 及大多數其他程式都會使用該檔案。`/usr/local/share/ca-certificates/` 是存放本機新增憑證的正確位置；`/usr/share/ca-certificates/` 則屬於發行版的套件。

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

（如果找不到 `update-ca-certificates`，請先執行 `apk add ca-certificates`。）

### Arch Linux

```sh
sudo trust anchor --store minica-ca.pem
```

### macOS

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain minica-ca.pem
```

或者連按兩下該檔案，在「鑰匙圈存取」中將其加入 *System* 鑰匙圈，開啟後把 *When using this certificate* 設為 *Always Trust*。Safari 與 Chrome 使用鑰匙圈；Firefox 則需要執行下方的額外步驟。

### Windows

以系統管理員身分執行（PowerShell）：

```powershell
Import-Certificate -FilePath .\minica-ca.pem -CertStoreLocation Cert:\LocalMachine\Root
```

或使用 `certutil -addstore -f Root minica-ca.pem`，或連按兩下 → *Install Certificate* → *Local Machine* → *Place all certificates in the following store* → *Trusted Root Certification Authorities*。Edge、Chrome 以及 .NET/PowerShell 使用此憑證存放區；Firefox 則需要執行下方的額外步驟。

### Android

Android 只能安裝副檔名為 `.crt`/`.cer` 的 DER 或 PEM 檔案：

```sh
openssl x509 -in minica-ca.pem -outform DER -out minica-ca.crt
```

將檔案複製到手機，然後前往 *Settings → Security → Encryption & credentials → Install a certificate → CA certificate*。Android 11 以上版本會警告必須從「設定」安裝憑證；上述路徑即是如此。Chrome 與大多數應用程式隨後便會信任它，但採用憑證綁定（certificate pinning）或自帶信任存放區的應用程式（以及部分使用自有網路堆疊的應用程式）則不會。

### iOS / iPadOS

在裝置上開啟 `.pem`（透過 AirDrop、郵件、檔案 App）→ *Settings → Profile Downloaded → Install*，然後前往 *Settings → General → About → Certificate Trust Settings* 啟用信任。

## 瀏覽器

Chrome、Edge 與 Safari 使用作業系統的憑證存放區，因此上述步驟已足夠。**Firefox** 除非另行設定，否則會使用自己的憑證存放區：

- Preferences → Privacy & Security → Certificates → *View Certificates* → *Authorities* → *Import* → 勾選 *Trust this CA to identify websites*；或
- 在 `about:config` 中將 `security.enterprise_roots.enabled` 設為 `true`，讓 Firefox 使用 Windows / macOS 的系統憑證存放區；或
- 在 Linux 上，匯入至設定檔的 NSS 資料庫：
  `certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.mozilla/firefox/<profile>`（`certutil` 來自 `libnss3-tools` / `nss-tools`）。

Linux 上的 Chromium 也有一個供使用者自行安裝 CA 的 NSS 存放區：
`certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.pki/nssdb`。

## 命令列工具與程式語言

### curl

```sh
curl --cacert minica-ca.pem https://intranet.example.com/
export CURL_CA_BUNDLE=/path/to/minica-ca.pem     # for a shell session
```

將 CA 安裝到系統憑證存放區之後（見上文），就不需要任何選項。`CURL_CA_BUNDLE` 會*取代*原有的憑證包，因此如果兩者都需要，請指向一個同時包含公開 CA 的檔案（例如將 MiniCA 的 PEM 附加到 `/etc/ssl/certs/ca-certificates.crt` 的副本中）。

### wget

```sh
wget --ca-certificate=minica-ca.pem https://intranet.example.com/
echo "ca_certificate = /path/to/minica-ca.pem" >> ~/.wgetrc
```

### Python

`urllib`、`http.client` 與 `ssl` 模組使用 OpenSSL 的預設路徑，也就是系統憑證存放區，並遵循 `SSL_CERT_FILE` / `SSL_CERT_DIR`。`requests` 程式庫（以及所有建構於其上的工具，包括 `pip`）則改用 `certifi` 憑證包：

```sh
export REQUESTS_CA_BUNDLE=/path/to/minica-ca.pem   # requests; replaces the bundle
export SSL_CERT_FILE=/path/to/minica-ca.pem        # ssl / urllib / httpx
pip config set global.cert /path/to/minica-ca.pem  # pip
```

若要同時保留公開 CA，請將 MiniCA 的 PEM 附加到 certifi 憑證包的副本（`python -m certifi` 會印出其路徑），再讓這些環境變數指向該副本。執行 `pip install pip-system-certs` 或使用 `truststore`，可讓 requests 改用作業系統的憑證存放區。

### Java / JVM（Kafka、Elasticsearch、Jenkins 等）

下載的 CA 信任存放區是可直接使用的 PKCS#12 信任存放區（密碼為 `changeit`，CA 以 `trustedCertEntry` 形式儲存）：

```sh
curl -fsSLo minica-truststore.p12 https://ca.example.com/minica/download/ca/<ca-id>/truststore
java -Djavax.net.ssl.trustStore=minica-truststore.p12 \
     -Djavax.net.ssl.trustStorePassword=changeit \
     -Djavax.net.ssl.trustStoreType=PKCS12 -jar app.jar
```

該信任存放區*只*包含 MiniCA 的 CA。若要改為將 CA 加入 JDK 的預設信任存放區（讓公開 CA 仍可正常運作）：

```sh
keytool -importcert -trustcacerts -noprompt -alias minica \
  -file minica-ca.pem -cacerts -storepass changeit
```

Kafka 用戶端請設定 `ssl.truststore.location=minica-truststore.p12`、`ssl.truststore.password=changeit`、`ssl.truststore.type=PKCS12`。

### Go

Go 使用系統憑證存放區（`crypto/x509` 在 Linux 上會讀取 `/etc/ssl/certs`），並遵循 `SSL_CERT_FILE` / `SSL_CERT_DIR`。若要在程式碼中加入 CA：

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

這會在 Node 內建的 CA *之外*額外加入。`--use-openssl-ca` 則讓 Node 改用系統憑證存放區。

### yt-dlp

yt-dlp 是 Python 程式，適用 Python 的規則：若已安裝 `certifi`（通常如此），它會使用 certifi 的憑證包，否則使用 OpenSSL 的預設憑證存放區。你可以將 CA 安裝到系統憑證存放區並移除或繞過 certifi，或是讓 yt-dlp 的 HTTP 堆疊指向同時包含兩者的憑證包：

```sh
cat "$(python3 -m certifi)" minica-ca.pem > ~/.config/yt-dlp/ca-bundle.pem
SSL_CERT_FILE=~/.config/yt-dlp/ca-bundle.pem REQUESTS_CA_BUNDLE=~/.config/yt-dlp/ca-bundle.pem yt-dlp https://media.intranet.example.com/...
```

請避免使用 `--no-check-certificates`；它會完全關閉驗證。

## 伺服器與服務

### Nginx

有三種不同的情況很容易混淆：

- **提供 MiniCA 簽發的憑證。** 下載該憑證的 *Bundle*（zip）——內含 `cert.pem`、`cert.key` 與 `ca.pem`——然後使用
  ```nginx
  ssl_certificate     /etc/nginx/tls/cert.pem;    # or cat cert.pem ca.pem > fullchain.pem
  ssl_certificate_key /etc/nginx/tls/cert.key;
  ```
  之後用戶端需要依照本頁所述安裝該 CA。
- **Nginx 作為 TLS 用戶端**（代理到出示 MiniCA 憑證的上游伺服器）：
  ```nginx
  proxy_ssl_verify on;
  proxy_ssl_trusted_certificate /etc/nginx/tls/minica-ca.pem;
  proxy_ssl_name upstream.example.com;
  ```
- **由 MiniCA 簽發的用戶端憑證（mTLS）：**
  ```nginx
  ssl_client_certificate /etc/nginx/tls/minica-ca.pem;
  ssl_verify_client on;
  ssl_crl /etc/nginx/tls/minica.crl.pem;   # optional: openssl crl -inform DER -in <crl> -out minica.crl.pem
  ```
  CRL 位於 `https://ca.example.com/minica/crl/<ca-id>`（DER 格式）。

### Docker

對於**映像檔**，請在建置時加入 CA，讓映像檔內的所有工具都能使用：

```dockerfile
# Debian/Ubuntu based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN update-ca-certificates
# Alpine based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN apk add --no-cache ca-certificates && update-ca-certificates
```

對於**無法重新建置的容器**，可以將已包含該 CA 的憑證包（例如在主機上安裝 CA 之後的主機 `/etc/ssl/certs/ca-certificates.crt`）掛載到映像檔原本的憑證包上，或透過上述環境變數讓容器內的工具指向它：

```yaml
    environment:
      SSL_CERT_FILE:        /etc/ssl/certs/ca-certificates.crt   # OpenSSL, Python ssl, Go, Ruby
      REQUESTS_CA_BUNDLE:   /etc/ssl/certs/ca-certificates.crt   # Python requests
      CURL_CA_BUNDLE:       /etc/ssl/certs/ca-certificates.crt   # curl
      NODE_EXTRA_CA_CERTS:  /etc/ssl/certs/ca-certificates.crt   # Node.js
    volumes:
      - /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro
```

若映像檔所基於的發行版將憑證包放在其他位置（RHEL 系列：`/etc/pki/tls/certs/ca-bundle.crt`），則需改用該路徑。

Docker *daemon* 會從 `/etc/docker/certs.d/<registry:port>/ca.crt` 信任私有 registry 的 CA，與系統憑證存放區無關。

### LLDAP

LLDAP 是伺服器：請為其 LDAPS 監聽埠提供由 MiniCA 簽發的憑證（下載該憑證的 bundle；金鑰為 `cert.key`）：

```toml
# lldap_config.toml
[ldaps_options]
enabled = true
port = 6360
cert_file = "/data/tls/cert.pem"
key_file = "/data/tls/cert.key"
```

或在環境變數中設定 `LLDAP_LDAPS_OPTIONS__ENABLED=true`、`LLDAP_LDAPS_OPTIONS__CERT_FILE=...`、`LLDAP_LDAPS_OPTIONS__KEY_FILE=...`。之後每個 LDAP 用戶端（Authelia、Nextcloud、Jellyfin 等）都需要在各自的信任存放區中加入 MiniCA 的 CA，做法請參考上文中其所執行的平台或程式語言的設定方式。

## 透過 Nginx 發布 MiniCA

使用 MiniCA 內建登入時，一個路徑前綴就夠了。MiniCA 會自行保護私有頁面，本指南則透過 `/minica/how-to-use` 公開存取：

```nginx
location /minica/ {
    proxy_pass http://minica:9988;
    include /etc/nginx/snippets/proxy.conf;
}
```

使用 SSO（Authelia、oauth2-proxy 等）時，該前綴受到保護，因此公開頁面需要單獨一條規則。請在這條規則中清除身分請求標頭，因為 MiniCA 會信任來自代理的這些標頭：

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

## 確認是否生效

```sh
openssl s_client -connect intranet.example.com:443 -servername intranet.example.com </dev/null 2>/dev/null | grep "Verify return code"
curl -v https://intranet.example.com/ 2>&1 | grep -E "SSL certificate verify|issuer"
```

`Verify return code: 0 (ok)` 表示用戶端已找到並信任該 CA。
