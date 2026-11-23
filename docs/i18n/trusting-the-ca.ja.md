<!-- source-sha256: 51e546526752332fcfc280e7dff9c74d662f180be9dc12f325b1f7754935dbb2 -->
# MiniCA 認証局を信頼する

MiniCA が発行した証明書は、クライアントが発行元の CA を信頼して初めて受け入れられます。このページでは、主要なプラットフォームとツール向けの手順をまとめています。すべての CA が持つ、2 つの公開ダウンロード（ログイン不要）から始めます。

| ダウンロード | URL | 用途 |
| --- | --- | --- |
| CA 証明書 (PEM) | `https://ca.example.com/minica/<ca-id>/download` | Java 以外のすべて |
| CA トラストストア (PKCS#12、パスワードは `changeit`) | `https://ca.example.com/minica/download/ca/<ca-id>/truststore` | Java / JVM アプリケーション |

どちらも、公開 CA 一覧 `https://ca.example.com/minica/` と CA のページからリンクされています。ファイル名は CA のコモンネームに由来し、例えば `Homelab_CA.pem` となります。以下の例ではこれを `minica-ca.pem` / `minica-ca.crt` と呼びます。

```sh
curl -fsSLo minica-ca.pem https://ca.example.com/minica/<ca-id>/download
openssl x509 -in minica-ca.pem -noout -subject -dates -fingerprint -sha256   # check what you got
```

クライアントにインストールするのは **CA 証明書**のみで、秘密鍵は決してインストールしません。CA が中間 CA の場合は、そのルート CA を（または両方を）インストールしてください。

## オペレーティングシステム

### Debian / Ubuntu

```sh
sudo cp minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt   # must end in .crt, PEM content
sudo update-ca-certificates
```

これにより CA が `/etc/ssl/certs/ca-certificates.crt` に追加されます。curl、wget、Python、Go、Node (`NODE_EXTRA_CA_CERTS` または `--use-openssl-ca` を使用)、apt など、システム上のほとんどのプログラムがこのファイルを使用します。ローカルで追加する証明書の置き場所は `/usr/local/share/ca-certificates/` が適切です。`/usr/share/ca-certificates/` はディストリビューションのパッケージが管理する場所です。

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

(`update-ca-certificates` がない場合は、先に `apk add ca-certificates` を実行してください。)

### Arch Linux

```sh
sudo trust anchor --store minica-ca.pem
```

### macOS

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain minica-ca.pem
```

または、ファイルをダブルクリックして Keychain Access の*システム*キーチェーンに追加し、それを開いて*この証明書を使用するとき*を*常に信頼*に設定します。Safari と Chrome はキーチェーンを使用しますが、Firefox は下記の追加手順が必要です。

### Windows

管理者として (PowerShell) 実行します。

```powershell
Import-Certificate -FilePath .\minica-ca.pem -CertStoreLocation Cert:\LocalMachine\Root
```

または `certutil -addstore -f Root minica-ca.pem` を実行するか、ダブルクリック → *証明書のインストール* → *ローカル コンピューター* → *証明書をすべて次のストアに配置する* → *信頼されたルート証明機関*の順に進みます。Edge、Chrome、.NET/PowerShell はこのストアを使用します。Firefox は下記の追加手順が必要です。

### Android

Android がインストールできるのは、`.crt`/`.cer` という名前の DER または PEM ファイルのみです。

```sh
openssl x509 -in minica-ca.pem -outform DER -out minica-ca.crt
```

ファイルを端末にコピーし、*設定 → セキュリティ → 暗号化と認証情報 → 証明書のインストール → CA 証明書*の順に進みます。Android 11 以降では、証明書は設定からインストールする必要があるという警告が表示されますが、上記がまさにその手順です。これで Chrome やほとんどのアプリはこの CA を信頼しますが、証明書ピンニングを行うアプリや独自のトラストストアを持つアプリ（および独自のネットワークスタックを使うアプリの一部）は信頼しません。

### iOS / iPadOS

端末上で `.pem` を開き (AirDrop、メール、ファイル)、*設定 → プロファイルがダウンロードされました → インストール*の順に進み、その後*設定 → 一般 → 情報 → 証明書信頼設定*で有効にします。

## ブラウザ

Chrome、Edge、Safari はオペレーティングシステムのストアを使用するため、上記の手順で十分です。**Firefox** は、設定を変えない限り独自のストアを保持します。

- 設定 → プライバシーとセキュリティ → 証明書 → *証明書を表示* → *認証局* → *インポート* → *この認証局を信頼してウェブサイトを識別する*にチェックを入れる。または、
- `about:config` で `security.enterprise_roots.enabled` を `true` に設定し、Firefox に Windows / macOS のシステムストアを使用させる。または、
- Linux では、プロファイルの NSS データベースにインポートする。
  `certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.mozilla/firefox/<profile>` (`certutil` は `libnss3-tools` / `nss-tools` に含まれます)。

Linux 上の Chromium にも、ユーザーがインストールした CA 用の NSS ストアがあります。
`certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.pki/nssdb`。

## コマンドラインツールと言語

### curl

```sh
curl --cacert minica-ca.pem https://intranet.example.com/
export CURL_CA_BUNDLE=/path/to/minica-ca.pem     # for a shell session
```

CA をシステムストア（上記）にインストールした後は、オプションは不要です。`CURL_CA_BUNDLE` はバンドルを*置き換える*ため、公開 CA も併用する必要がある場合は、公開 CA を含むファイルを指定してください（例: `/etc/ssl/certs/ca-certificates.crt` のコピーに MiniCA の PEM を追記する）。

### wget

```sh
wget --ca-certificate=minica-ca.pem https://intranet.example.com/
echo "ca_certificate = /path/to/minica-ca.pem" >> ~/.wgetrc
```

### Python

`urllib`、`http.client`、`ssl` モジュールは OpenSSL のデフォルトパス、つまりシステムストアを使用し、`SSL_CERT_FILE` / `SSL_CERT_DIR` も尊重します。`requests` ライブラリ（`pip` を含め、それを基盤とするすべて）は、代わりに `certifi` バンドルを使用します。

```sh
export REQUESTS_CA_BUNDLE=/path/to/minica-ca.pem   # requests; replaces the bundle
export SSL_CERT_FILE=/path/to/minica-ca.pem        # ssl / urllib / httpx
pip config set global.cert /path/to/minica-ca.pem  # pip
```

公開 CA も維持するには、certifi のバンドル（`python -m certifi` でパスが表示されます）のコピーに MiniCA の PEM を追記し、各変数をそのコピーに向けてください。`pip install pip-system-certs` または `truststore` を使うと、requests がオペレーティングシステムのストアを使用するようになります。

### Java / JVM (Kafka, Elasticsearch, Jenkins, ...)

CA トラストストアのダウンロードは、すぐに使える PKCS#12 トラストストアです（パスワードは `changeit`、CA は `trustedCertEntry` として格納されています）。

```sh
curl -fsSLo minica-truststore.p12 https://ca.example.com/minica/download/ca/<ca-id>/truststore
java -Djavax.net.ssl.trustStore=minica-truststore.p12 \
     -Djavax.net.ssl.trustStorePassword=changeit \
     -Djavax.net.ssl.trustStoreType=PKCS12 -jar app.jar
```

このトラストストアには MiniCA の CA*だけ*が含まれています。代わりに JDK のデフォルトストアに CA を追加するには（公開 CA も引き続き使えます）、次のようにします。

```sh
keytool -importcert -trustcacerts -noprompt -alias minica \
  -file minica-ca.pem -cacerts -storepass changeit
```

Kafka クライアントでは `ssl.truststore.location=minica-truststore.p12`、`ssl.truststore.password=changeit`、`ssl.truststore.type=PKCS12` を指定します。

### Go

Go はシステムストアを使用し（`crypto/x509` は Linux では `/etc/ssl/certs` を読み込みます）、`SSL_CERT_FILE` / `SSL_CERT_DIR` も尊重します。コードから CA を追加するには次のようにします。

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

これは Node に組み込まれた CA に*追加*されます。`--use-openssl-ca` を指定すると、代わりにシステムストアを使用します。

### yt-dlp

yt-dlp は Python プログラムであり、Python のルールに従います。`certifi` がインストールされている場合（通常はそうです）は certifi のバンドルを、そうでなければ OpenSSL のデフォルトストアを使用します。CA をシステムストアにインストールして certifi を削除 / 回避するか、yt-dlp の HTTP スタックを両方を含むバンドルに向けてください。

```sh
cat "$(python3 -m certifi)" minica-ca.pem > ~/.config/yt-dlp/ca-bundle.pem
SSL_CERT_FILE=~/.config/yt-dlp/ca-bundle.pem REQUESTS_CA_BUNDLE=~/.config/yt-dlp/ca-bundle.pem yt-dlp https://media.intranet.example.com/...
```

`--no-check-certificates` は検証を完全に無効にしてしまうため、使用しないでください。

## サーバーとサービス

### Nginx

混同しやすい 3 つのケースがあります。

- **MiniCA が発行した証明書を提供する場合。** 証明書の*バンドル* (zip) をダウンロードします。中身は `cert.pem`、`cert.key`、`ca.pem` です。そして次のように設定します。
  ```nginx
  ssl_certificate     /etc/nginx/tls/cert.pem;    # or cat cert.pem ca.pem > fullchain.pem
  ssl_certificate_key /etc/nginx/tls/cert.key;
  ```
  この場合、クライアント側には、このページで説明している方法で CA をインストールする必要があります。
- **Nginx が TLS クライアントになる場合** (MiniCA の証明書を提示するアップストリームへプロキシする):
  ```nginx
  proxy_ssl_verify on;
  proxy_ssl_trusted_certificate /etc/nginx/tls/minica-ca.pem;
  proxy_ssl_name upstream.example.com;
  ```
- **MiniCA が発行したクライアント証明書 (mTLS) を使う場合:**
  ```nginx
  ssl_client_certificate /etc/nginx/tls/minica-ca.pem;
  ssl_verify_client on;
  ssl_crl /etc/nginx/tls/minica.crl.pem;   # optional: openssl crl -inform DER -in <crl> -out minica.crl.pem
  ```
  CRL は `https://ca.example.com/minica/crl/<ca-id>` にあります (DER 形式)。

### Docker

**イメージ**の場合は、ビルド時に CA を追加して、イメージ内のすべてのツールから見えるようにします。

```dockerfile
# Debian/Ubuntu based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN update-ca-certificates
# Alpine based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN apk add --no-cache ca-certificates && update-ca-certificates
```

**再ビルドできないコンテナ**の場合は、CA を含むバンドル（例: ホストに CA をインストールした後のホストの `/etc/ssl/certs/ca-certificates.crt`）をイメージのバンドルの上にマウントするか、上記の環境変数を通じて、コンテナ内のツールにそのバンドルを指定します。

```yaml
    environment:
      SSL_CERT_FILE:        /etc/ssl/certs/ca-certificates.crt   # OpenSSL, Python ssl, Go, Ruby
      REQUESTS_CA_BUNDLE:   /etc/ssl/certs/ca-certificates.crt   # Python requests
      CURL_CA_BUNDLE:       /etc/ssl/certs/ca-certificates.crt   # curl
      NODE_EXTRA_CA_CERTS:  /etc/ssl/certs/ca-certificates.crt   # Node.js
    volumes:
      - /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro
```

バンドルを別の場所に置くディストリビューション（RHEL 系: `/etc/pki/tls/certs/ca-bundle.crt`）をベースにしたイメージでは、そのパスを使用してください。

Docker の*デーモン*は、システムストアとは無関係に、`/etc/docker/certs.d/<registry:port>/ca.crt` にあるプライベートレジストリの CA を信頼します。

### LLDAP

LLDAP はサーバーです。LDAPS リスナー用に、MiniCA が発行した証明書を与えます（証明書のバンドルをダウンロードします。鍵は `cert.key` です）。

```toml
# lldap_config.toml
[ldaps_options]
enabled = true
port = 6360
cert_file = "/data/tls/cert.pem"
key_file = "/data/tls/cert.key"
```

または、環境変数で `LLDAP_LDAPS_OPTIONS__ENABLED=true`、`LLDAP_LDAPS_OPTIONS__CERT_FILE=...`、`LLDAP_LDAPS_OPTIONS__KEY_FILE=...` を設定します。その場合、すべての LDAP クライアント (Authelia、Nextcloud、Jellyfin など) は、それぞれが動作するプラットフォームや言語に応じて、上記の手順に従い、独自のトラストストアに MiniCA の CA を登録する必要があります。

## Nginx 経由で MiniCA を公開する

MiniCA 独自のログインを使う場合、プレフィックスは 1 つで十分です。非公開ページは MiniCA 自身が保護し、このガイドは `/minica/how-to-use` で公開されたままになります。

```nginx
location /minica/ {
    proxy_pass http://minica:9988;
    include /etc/nginx/snippets/proxy.conf;
}
```

SSO（Authelia、oauth2-proxy など）を使う場合はプレフィックスが保護されるため、公開ページには専用のルールが 1 つ必要です。MiniCA はプロキシから届いた ID ヘッダーを信頼するので、このルールでは ID ヘッダーを必ず空にしてください。

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

## 動作の確認

```sh
openssl s_client -connect intranet.example.com:443 -servername intranet.example.com </dev/null 2>/dev/null | grep "Verify return code"
curl -v https://intranet.example.com/ 2>&1 | grep -E "SSL certificate verify|issuer"
```

`Verify return code: 0 (ok)` と表示されれば、クライアントが CA を見つけて信頼したことを意味します。
