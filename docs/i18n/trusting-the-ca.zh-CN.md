<!-- source-sha256: 51e546526752332fcfc280e7dff9c74d662f180be9dc12f325b1f7754935dbb2 -->
# 信任 MiniCA 证书颁发机构

只有当客户端信任签发证书的 CA 之后，才会接受由 MiniCA 签发的证书。本文汇总了常见平台和工具的配置方法。所有操作都从每个 CA 都提供的两个公开下载项开始（无需登录）：

| 下载项 | URL | 适用场景 |
| --- | --- | --- |
| CA 证书（PEM） | `https://ca.example.com/minica/<ca-id>/download` | 除 Java 以外的所有场景 |
| CA 信任库（PKCS#12，密码为 `changeit`） | `https://ca.example.com/minica/download/ca/<ca-id>/truststore` | Java / JVM 应用程序 |

这两项也可以从公开的 CA 索引页 `https://ca.example.com/minica/` 以及 CA 页面中找到链接。文件以 CA 的通用名称（common name）命名，例如 `Homelab_CA.pem`；下文的示例将其称为 `minica-ca.pem` / `minica-ca.crt`。

```sh
curl -fsSLo minica-ca.pem https://ca.example.com/minica/<ca-id>/download
openssl x509 -in minica-ca.pem -noout -subject -dates -fingerprint -sha256   # check what you got
```

客户端上只需要安装 **CA 证书**，绝不要安装私钥。如果该 CA 是中间 CA，请安装其根证书（或同时安装两者）。

## 操作系统

### Debian / Ubuntu

```sh
sudo cp minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt   # must end in .crt, PEM content
sudo update-ca-certificates
```

这会把该 CA 添加到 `/etc/ssl/certs/ca-certificates.crt`，系统上的 curl、wget、Python、Go、Node（配合 `NODE_EXTRA_CA_CERTS` 或 `--use-openssl-ca`）、apt 以及大多数其他程序都会使用这个文件。`/usr/local/share/ca-certificates/` 是存放本地新增证书的正确位置；`/usr/share/ca-certificates/` 则属于发行版软件包。

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

（如果缺少 `update-ca-certificates`，请先执行 `apk add ca-certificates`。）

### Arch Linux

```sh
sudo trust anchor --store minica-ca.pem
```

### macOS

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain minica-ca.pem
```

或者双击该文件，在“钥匙串访问”中将其添加到 *System*（系统）钥匙串，打开该证书并将 *使用此证书时* 设置为 *始终信任*。Safari 和 Chrome 使用钥匙串；Firefox 还需要执行下文的额外步骤。

### Windows

以管理员身份（PowerShell）：

```powershell
Import-Certificate -FilePath .\minica-ca.pem -CertStoreLocation Cert:\LocalMachine\Root
```

或者使用 `certutil -addstore -f Root minica-ca.pem`，或者双击 → *安装证书* → *本地计算机* → *将所有的证书都放入下列存储* → *受信任的根证书颁发机构*。Edge、Chrome 以及 .NET/PowerShell 使用该证书存储；Firefox 还需要执行下文的额外步骤。

### Android

Android 只能安装扩展名为 `.crt`/`.cer` 的 DER 或 PEM 文件：

```sh
openssl x509 -in minica-ca.pem -outform DER -out minica-ca.crt
```

将其复制到手机，然后依次进入 *设置 → 安全 → 加密与凭据 → 安装证书 → CA 证书*。Android 11 及以上版本会提示必须通过“设置”安装证书，上述路径正是如此。之后 Chrome 和大多数应用都会信任该证书，但固定证书（pinning）或自带信任库的应用（以及一些使用自有网络栈的应用）不会信任它。

### iOS / iPadOS

在设备上打开 `.pem` 文件（通过 AirDrop、邮件或“文件”）→ *设置 → 已下载描述文件 → 安装*，然后在 *设置 → 通用 → 关于本机 → 证书信任设置* 中启用它。

## 浏览器

Chrome、Edge 和 Safari 使用操作系统的证书存储，因此上述步骤已经足够。**Firefox** 除非另行设置，否则使用自己的证书存储：

- 偏好设置 → 隐私与安全 → 证书 → *查看证书* → *证书颁发机构* → *导入* → 勾选 *信任由此证书颁发机构来标识网站*；或者
- 在 `about:config` 中将 `security.enterprise_roots.enabled` 设置为 `true`，让 Firefox 使用 Windows / macOS 的系统证书存储；或者
- 在 Linux 上，导入到该配置文件的 NSS 数据库：
  `certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.mozilla/firefox/<profile>`（`certutil` 来自 `libnss3-tools` / `nss-tools`）。

Linux 上的 Chromium 也有一个用于用户安装 CA 的 NSS 存储：
`certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.pki/nssdb`。

## 命令行工具与编程语言

### curl

```sh
curl --cacert minica-ca.pem https://intranet.example.com/
export CURL_CA_BUNDLE=/path/to/minica-ca.pem     # for a shell session
```

将 CA 安装到系统证书存储（见上文）之后，就不需要任何选项了。`CURL_CA_BUNDLE` 会*替换*默认证书包，因此如果你同时需要公共 CA，请让它指向一个同时包含公共 CA 的文件（例如把 MiniCA 的 PEM 追加到 `/etc/ssl/certs/ca-certificates.crt` 的副本中）。

### wget

```sh
wget --ca-certificate=minica-ca.pem https://intranet.example.com/
echo "ca_certificate = /path/to/minica-ca.pem" >> ~/.wgetrc
```

### Python

`urllib`、`http.client` 和 `ssl` 模块使用 OpenSSL 的默认路径，即系统证书存储，并遵循 `SSL_CERT_FILE` / `SSL_CERT_DIR`。`requests` 库（以及所有基于它的程序，包括 `pip`）则改用 `certifi` 证书包：

```sh
export REQUESTS_CA_BUNDLE=/path/to/minica-ca.pem   # requests; replaces the bundle
export SSL_CERT_FILE=/path/to/minica-ca.pem        # ssl / urllib / httpx
pip config set global.cert /path/to/minica-ca.pem  # pip
```

若要同时保留公共 CA，请把 MiniCA 的 PEM 追加到 certifi 证书包的副本中（`python -m certifi` 会打印其路径），然后让这些变量指向该副本。执行 `pip install pip-system-certs` 或安装 `truststore` 可以让 requests 改用操作系统的证书存储。

### Java / JVM (Kafka, Elasticsearch, Jenkins, ...)

CA 信任库下载项是一个开箱即用的 PKCS#12 信任库（密码为 `changeit`，CA 以 `trustedCertEntry` 形式存储）：

```sh
curl -fsSLo minica-truststore.p12 https://ca.example.com/minica/download/ca/<ca-id>/truststore
java -Djavax.net.ssl.trustStore=minica-truststore.p12 \
     -Djavax.net.ssl.trustStorePassword=changeit \
     -Djavax.net.ssl.trustStoreType=PKCS12 -jar app.jar
```

该信任库*只*包含 MiniCA 的 CA。如果想改为把该 CA 添加到 JDK 的默认信任库（这样公共 CA 仍然可用）：

```sh
keytool -importcert -trustcacerts -noprompt -alias minica \
  -file minica-ca.pem -cacerts -storepass changeit
```

Kafka 客户端使用 `ssl.truststore.location=minica-truststore.p12`、`ssl.truststore.password=changeit`、`ssl.truststore.type=PKCS12`。

### Go

Go 使用系统证书存储（在 Linux 上 `crypto/x509` 会读取 `/etc/ssl/certs`），并遵循 `SSL_CERT_FILE` / `SSL_CERT_DIR`。若要在代码中添加 CA：

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

这会在 Node 内置 CA 的基础上*追加*。`--use-openssl-ca` 则让 Node 改用系统证书存储。

### yt-dlp

yt-dlp 是一个 Python 程序，遵循 Python 的规则：如果安装了 `certifi`（通常如此），它就使用 certifi 的证书包，否则使用 OpenSSL 的默认证书存储。你可以把 CA 安装到系统证书存储并移除 / 绕过 certifi，或者让 yt-dlp 的 HTTP 栈指向一个同时包含两者的证书包：

```sh
cat "$(python3 -m certifi)" minica-ca.pem > ~/.config/yt-dlp/ca-bundle.pem
SSL_CERT_FILE=~/.config/yt-dlp/ca-bundle.pem REQUESTS_CA_BUNDLE=~/.config/yt-dlp/ca-bundle.pem yt-dlp https://media.intranet.example.com/...
```

请避免使用 `--no-check-certificates`，它会完全关闭证书校验。

## 服务器与服务

### Nginx

有三件不同的事情很容易混淆：

- **提供由 MiniCA 签发的证书。** 下载该证书的 *Bundle*（zip）——其中包含 `cert.pem`、`cert.key` 和 `ca.pem`——然后使用
  ```nginx
  ssl_certificate     /etc/nginx/tls/cert.pem;    # or cat cert.pem ca.pem > fullchain.pem
  ssl_certificate_key /etc/nginx/tls/cert.key;
  ```
  之后客户端需要按照本文所述安装该 CA。
- **Nginx 作为 TLS 客户端**（代理到出示 MiniCA 证书的上游）：
  ```nginx
  proxy_ssl_verify on;
  proxy_ssl_trusted_certificate /etc/nginx/tls/minica-ca.pem;
  proxy_ssl_name upstream.example.com;
  ```
- **由 MiniCA 签发的客户端证书（mTLS）：**
  ```nginx
  ssl_client_certificate /etc/nginx/tls/minica-ca.pem;
  ssl_verify_client on;
  ssl_crl /etc/nginx/tls/minica.crl.pem;   # optional: openssl crl -inform DER -in <crl> -out minica.crl.pem
  ```
  CRL 位于 `https://ca.example.com/minica/crl/<ca-id>`（DER 格式）。

### Docker

对于**镜像**，请在构建时添加该 CA，这样镜像中的所有工具都能识别它：

```dockerfile
# Debian/Ubuntu based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN update-ca-certificates
# Alpine based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN apk add --no-cache ca-certificates && update-ca-certificates
```

对于**无法重新构建的容器**，可以把一个已包含该 CA 的证书包（例如在宿主机上安装 CA 之后的宿主机 `/etc/ssl/certs/ca-certificates.crt`）挂载到镜像自带证书包的位置，或者通过上文所述的环境变量让容器内的工具指向它：

```yaml
    environment:
      SSL_CERT_FILE:        /etc/ssl/certs/ca-certificates.crt   # OpenSSL, Python ssl, Go, Ruby
      REQUESTS_CA_BUNDLE:   /etc/ssl/certs/ca-certificates.crt   # Python requests
      CURL_CA_BUNDLE:       /etc/ssl/certs/ca-certificates.crt   # curl
      NODE_EXTRA_CA_CERTS:  /etc/ssl/certs/ca-certificates.crt   # Node.js
    volumes:
      - /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro
```

如果镜像基于把证书包放在其他位置的发行版（RHEL 系：`/etc/pki/tls/certs/ca-bundle.crt`），则需要改用那个路径。

Docker *守护进程*从 `/etc/docker/certs.d/<registry:port>/ca.crt` 信任私有镜像仓库的 CA，与系统证书存储无关。

### LLDAP

LLDAP 是一个服务器：请为它的 LDAPS 监听器提供一张由 MiniCA 签发的证书（下载该证书的 bundle；私钥是 `cert.key`）：

```toml
# lldap_config.toml
[ldaps_options]
enabled = true
port = 6360
cert_file = "/data/tls/cert.pem"
key_file = "/data/tls/cert.key"
```

或者在环境变量中设置 `LLDAP_LDAPS_OPTIONS__ENABLED=true`、`LLDAP_LDAPS_OPTIONS__CERT_FILE=...`、`LLDAP_LDAPS_OPTIONS__KEY_FILE=...`。之后，每个 LDAP 客户端（Authelia、Nextcloud、Jellyfin 等）都需要在自己的信任库中加入 MiniCA 的 CA，具体方法见上文针对其所在平台或语言的说明。

## 通过 Nginx 发布 MiniCA

使用 MiniCA 自带登录时，一个路径前缀就够了。MiniCA 会自行保护私有页面，本指南则通过 `/minica/how-to-use` 公开访问：

```nginx
location /minica/ {
    proxy_pass http://minica:9988;
    include /etc/nginx/snippets/proxy.conf;
}
```

使用 SSO（Authelia、oauth2-proxy 等）时，该前缀受到保护，因此公开页面需要单独一条规则。请在这条规则中清除身份请求头，因为 MiniCA 会信任来自代理的这些请求头：

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

## 验证是否生效

```sh
openssl s_client -connect intranet.example.com:443 -servername intranet.example.com </dev/null 2>/dev/null | grep "Verify return code"
curl -v https://intranet.example.com/ 2>&1 | grep -E "SSL certificate verify|issuer"
```

出现 `Verify return code: 0 (ok)` 表示客户端找到并信任了该 CA。
