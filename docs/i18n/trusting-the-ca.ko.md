<!-- source-sha256: 51e546526752332fcfc280e7dff9c74d662f180be9dc12f325b1f7754935dbb2 -->
# MiniCA 인증 기관 신뢰하기

MiniCA가 발급한 인증서는 클라이언트가 발급 CA를 신뢰해야만 받아들여집니다.
이 문서는 주요 플랫폼과 도구별 설정 방법을 모아 놓은 것입니다. 모든 CA가
가지고 있는 두 가지 공개 다운로드(로그인 불필요)에서 시작합니다.

| 다운로드 | URL | 용도 |
| --- | --- | --- |
| CA 인증서 (PEM) | `https://ca.example.com/minica/<ca-id>/download` | Java를 제외한 모든 경우 |
| CA 트러스트스토어 (PKCS#12, 비밀번호 `changeit`) | `https://ca.example.com/minica/download/ca/<ca-id>/truststore` | Java / JVM 애플리케이션 |

두 파일 모두 `https://ca.example.com/minica/`의 공개 CA 목록과 CA 페이지에서도
링크되어 있습니다. 파일 이름은 CA의 common name을 따르며, 예를 들어
`Homelab_CA.pem`입니다. 아래 예제에서는 이 파일을 `minica-ca.pem` / `minica-ca.crt`라고 부릅니다.

```sh
curl -fsSLo minica-ca.pem https://ca.example.com/minica/<ca-id>/download
openssl x509 -in minica-ca.pem -noout -subject -dates -fingerprint -sha256   # check what you got
```

클라이언트에는 **CA 인증서**만 설치하며, 개인 키는 절대 설치하지 않습니다.
CA가 중간 CA라면 루트 CA를 대신(또는 함께) 설치하십시오.

## 운영체제

### Debian / Ubuntu

```sh
sudo cp minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt   # must end in .crt, PEM content
sudo update-ca-certificates
```

이렇게 하면 CA가 `/etc/ssl/certs/ca-certificates.crt`에 추가되며, curl, wget,
Python, Go, Node(`NODE_EXTRA_CA_CERTS` 또는 `--use-openssl-ca` 사용 시), apt 및
시스템의 대부분의 다른 프로그램이 이 파일을 사용합니다. `/usr/local/share/ca-certificates/`는
로컬에서 추가하는 인증서를 두는 올바른 위치이고, `/usr/share/ca-certificates/`는
배포판 패키지가 관리하는 위치입니다.

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

(`update-ca-certificates`가 없다면 먼저 `apk add ca-certificates`를 실행하십시오.)

### Arch Linux

```sh
sudo trust anchor --store minica-ca.pem
```

### macOS

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain minica-ca.pem
```

또는 파일을 더블 클릭하여 키체인 접근의 *시스템* 키체인에 추가한 다음,
인증서를 열고 *이 인증서 사용 시*를 *항상 신뢰*로 설정합니다. Safari와
Chrome은 키체인을 사용하며, Firefox는 아래의 추가 단계가 필요합니다.

### Windows

관리자 권한(PowerShell)으로 실행합니다.

```powershell
Import-Certificate -FilePath .\minica-ca.pem -CertStoreLocation Cert:\LocalMachine\Root
```

또는 `certutil -addstore -f Root minica-ca.pem`을 사용하거나, 더블 클릭 → *인증서
설치* → *로컬 컴퓨터* → *모든 인증서를 다음 저장소에 저장* →
*신뢰할 수 있는 루트 인증 기관*을 선택합니다. Edge, Chrome 및
.NET/PowerShell은 이 저장소를 사용하며, Firefox는 아래의 추가 단계가 필요합니다.

### Android

Android는 `.crt`/`.cer` 이름의 DER 또는 PEM 파일만 설치할 수 있습니다.

```sh
openssl x509 -in minica-ca.pem -outform DER -out minica-ca.crt
```

파일을 휴대폰으로 복사한 다음 *설정 → 보안 → 암호화 및 사용자 인증 정보 →
인증서 설치 → CA 인증서*로 이동합니다. Android 11 이상에서는 인증서를 설정에서
설치해야 한다는 경고가 표시되는데, 위의 경로가 바로 그 방법입니다.
이후 Chrome과 대부분의 앱은 이 인증서를 신뢰하지만, 인증서 피닝을 사용하거나
자체 트러스트 스토어를 포함하는 앱(그리고 자체 네트워크 스택을 사용하는 일부 앱)은 신뢰하지 않습니다.

### iOS / iPadOS

기기에서 `.pem` 파일을 열고(AirDrop, 메일, 파일 앱) → *설정 → 프로파일이
다운로드됨 → 설치*를 선택한 다음, *설정 → 일반 → 정보 →
인증서 신뢰 설정*에서 활성화합니다.

## 브라우저

Chrome, Edge, Safari는 운영체제 저장소를 사용하므로 위의 단계만으로 충분합니다.
**Firefox**는 별도로 지정하지 않으면 자체 저장소를 유지합니다.

- 환경설정 → 개인 정보 및 보안 → 인증서 → *인증서 보기* →
  *인증 기관* → *가져오기* → *이 인증 기관을 웹 사이트 식별에 신뢰* 체크, 또는
- `about:config`에서 `security.enterprise_roots.enabled`를 `true`로 설정하여
  Firefox가 Windows / macOS 시스템 저장소를 사용하도록 하거나,
- Linux에서는 프로필의 NSS 데이터베이스로 가져옵니다.
  `certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.mozilla/firefox/<profile>` (`certutil`은 `libnss3-tools` / `nss-tools`에 포함되어 있습니다).

Linux의 Chromium에도 사용자가 설치한 CA를 위한 NSS 저장소가 있습니다.
`certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.pki/nssdb`.

## 명령줄 도구와 프로그래밍 언어

### curl

```sh
curl --cacert minica-ca.pem https://intranet.example.com/
export CURL_CA_BUNDLE=/path/to/minica-ca.pem     # for a shell session
```

위에서 설명한 대로 CA를 시스템 저장소에 설치했다면 별도의 옵션은 필요 없습니다.
`CURL_CA_BUNDLE`은 번들을 *대체*하므로, 공인 CA도 함께 필요하다면 공인 CA가 들어 있는
파일을 가리키도록 하십시오(예: `/etc/ssl/certs/ca-certificates.crt`의 사본에 MiniCA PEM을 덧붙입니다).

### wget

```sh
wget --ca-certificate=minica-ca.pem https://intranet.example.com/
echo "ca_certificate = /path/to/minica-ca.pem" >> ~/.wgetrc
```

### Python

`urllib`, `http.client`, `ssl` 모듈은 OpenSSL의 기본 경로, 즉 시스템 저장소를 사용하며
`SSL_CERT_FILE` / `SSL_CERT_DIR`을 따릅니다. `requests` 라이브러리(그리고 `pip`을 포함해
이를 기반으로 하는 모든 것)는 대신 `certifi` 번들을 사용합니다.

```sh
export REQUESTS_CA_BUNDLE=/path/to/minica-ca.pem   # requests; replaces the bundle
export SSL_CERT_FILE=/path/to/minica-ca.pem        # ssl / urllib / httpx
pip config set global.cert /path/to/minica-ca.pem  # pip
```

공인 CA도 함께 유지하려면 certifi 번들의 사본(`python -m certifi`가 경로를 출력합니다)에
MiniCA PEM을 덧붙이고, 변수들이 그 사본을 가리키도록 하십시오. `pip install pip-system-certs`
또는 `truststore`를 사용하면 requests가 대신 운영체제 저장소를 사용합니다.

### Java / JVM (Kafka, Elasticsearch, Jenkins, ...)

CA 트러스트스토어 다운로드 파일은 바로 사용할 수 있는 PKCS#12 트러스트스토어입니다(비밀번호
`changeit`, CA는 `trustedCertEntry`로 저장됨).

```sh
curl -fsSLo minica-truststore.p12 https://ca.example.com/minica/download/ca/<ca-id>/truststore
java -Djavax.net.ssl.trustStore=minica-truststore.p12 \
     -Djavax.net.ssl.trustStorePassword=changeit \
     -Djavax.net.ssl.trustStoreType=PKCS12 -jar app.jar
```

이 트러스트스토어에는 MiniCA CA *만* 들어 있습니다. 대신 JDK의 기본 저장소에 CA를 추가하려면
(공인 CA도 계속 동작하도록):

```sh
keytool -importcert -trustcacerts -noprompt -alias minica \
  -file minica-ca.pem -cacerts -storepass changeit
```

Kafka 클라이언트는 `ssl.truststore.location=minica-truststore.p12`,
`ssl.truststore.password=changeit`, `ssl.truststore.type=PKCS12`를 사용합니다.

### Go

Go는 시스템 저장소를 사용하며(`crypto/x509`는 Linux에서 `/etc/ssl/certs`를 읽습니다)
`SSL_CERT_FILE` / `SSL_CERT_DIR`을 따릅니다. 코드에서 CA를 추가하려면 다음과 같이 합니다.

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

이 방법은 Node에 내장된 CA에 *추가*합니다. `--use-openssl-ca`를 사용하면 Node가
대신 시스템 저장소를 사용합니다.

### yt-dlp

yt-dlp는 Python 프로그램이므로 Python의 규칙을 따릅니다. `certifi`가 설치되어 있으면(일반적인 경우)
certifi의 번들을 사용하고, 그렇지 않으면 OpenSSL의 기본 저장소를 사용합니다. CA를 시스템 저장소에 설치하고
certifi를 제거하거나 우회하든지, 아니면 yt-dlp의 HTTP 스택이 둘 다 포함된 번들을 가리키도록 합니다.

```sh
cat "$(python3 -m certifi)" minica-ca.pem > ~/.config/yt-dlp/ca-bundle.pem
SSL_CERT_FILE=~/.config/yt-dlp/ca-bundle.pem REQUESTS_CA_BUNDLE=~/.config/yt-dlp/ca-bundle.pem yt-dlp https://media.intranet.example.com/...
```

`--no-check-certificates`는 사용하지 마십시오. 검증을 완전히 끄는 옵션입니다.

## 서버와 서비스

### Nginx

혼동하기 쉬운 세 가지 경우가 있습니다.

- **MiniCA가 발급한 인증서 제공하기.** 인증서의
  *Bundle*(zip)을 다운로드하면 `cert.pem`, `cert.key`, `ca.pem`이 들어 있으며, 다음과 같이 사용합니다.
  ```nginx
  ssl_certificate     /etc/nginx/tls/cert.pem;    # or cat cert.pem ca.pem > fullchain.pem
  ssl_certificate_key /etc/nginx/tls/cert.key;
  ```
  이 경우 클라이언트에는 이 문서에서 설명한 대로 CA가 설치되어 있어야 합니다.
- **TLS 클라이언트로서의 Nginx** (MiniCA 인증서를 제시하는 업스트림으로
  프록시하는 경우):
  ```nginx
  proxy_ssl_verify on;
  proxy_ssl_trusted_certificate /etc/nginx/tls/minica-ca.pem;
  proxy_ssl_name upstream.example.com;
  ```
- **MiniCA가 발급한 클라이언트 인증서(mTLS):**
  ```nginx
  ssl_client_certificate /etc/nginx/tls/minica-ca.pem;
  ssl_verify_client on;
  ssl_crl /etc/nginx/tls/minica.crl.pem;   # optional: openssl crl -inform DER -in <crl> -out minica.crl.pem
  ```
  CRL은 `https://ca.example.com/minica/crl/<ca-id>`(DER)에 있습니다.

### Docker

**이미지**의 경우, 이미지 안의 모든 도구가 CA를 인식하도록 빌드 시점에 CA를 추가합니다.

```dockerfile
# Debian/Ubuntu based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN update-ca-certificates
# Alpine based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN apk add --no-cache ca-certificates && update-ca-certificates
```

**다시 빌드할 수 없는 컨테이너**의 경우, CA가 이미 들어 있는 번들(예: 호스트에 CA를 설치한 뒤의
호스트의 `/etc/ssl/certs/ca-certificates.crt`)을 이미지의 번들 위에 마운트하거나, 위에서 설명한
환경 변수를 통해 내부 도구가 그 번들을 가리키도록 합니다.

```yaml
    environment:
      SSL_CERT_FILE:        /etc/ssl/certs/ca-certificates.crt   # OpenSSL, Python ssl, Go, Ruby
      REQUESTS_CA_BUNDLE:   /etc/ssl/certs/ca-certificates.crt   # Python requests
      CURL_CA_BUNDLE:       /etc/ssl/certs/ca-certificates.crt   # curl
      NODE_EXTRA_CA_CERTS:  /etc/ssl/certs/ca-certificates.crt   # Node.js
    volumes:
      - /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro
```

번들을 다른 위치에 두는 배포판 기반 이미지
(RHEL 계열: `/etc/pki/tls/certs/ca-bundle.crt`)에서는 해당 경로를 대신 사용해야 합니다.

Docker *데몬*은 시스템 저장소와는 별개로
`/etc/docker/certs.d/<registry:port>/ca.crt`에서 프라이빗 레지스트리의 CA를 신뢰합니다.

### LLDAP

LLDAP는 서버이므로, LDAPS 리스너에 사용할 MiniCA 발급 인증서를 제공해야 합니다
(인증서의 번들을 다운로드하며, 키는 `cert.key`입니다).

```toml
# lldap_config.toml
[ldaps_options]
enabled = true
port = 6360
cert_file = "/data/tls/cert.pem"
key_file = "/data/tls/cert.key"
```

또는 환경 변수로 `LLDAP_LDAPS_OPTIONS__ENABLED=true`, `LLDAP_LDAPS_OPTIONS__CERT_FILE=...`,
`LLDAP_LDAPS_OPTIONS__KEY_FILE=...`를 설정합니다. 이후 모든 LDAP 클라이언트
(Authelia, Nextcloud, Jellyfin, ...)는 실행되는 플랫폼이나 언어에 맞춰 위의 방법에 따라
자체 트러스트 스토어에 MiniCA CA를 설치해야 합니다.

## Nginx를 통해 MiniCA 게시하기

MiniCA 자체 로그인을 사용하면 접두사 하나로 충분합니다. 비공개 페이지는 MiniCA가 직접 보호하며, 이 가이드는 `/minica/how-to-use`에서 계속 공개됩니다.

```nginx
location /minica/ {
    proxy_pass http://minica:9988;
    include /etc/nginx/snippets/proxy.conf;
}
```

SSO(Authelia, oauth2-proxy 등)를 사용하면 접두사가 보호되므로 공개 페이지에는 별도의 규칙이 하나 필요합니다. MiniCA는 프록시에서 온 신원 헤더를 신뢰하므로 이 규칙에서는 신원 헤더를 반드시 비워 두십시오.

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

## 동작 확인

```sh
openssl s_client -connect intranet.example.com:443 -servername intranet.example.com </dev/null 2>/dev/null | grep "Verify return code"
curl -v https://intranet.example.com/ 2>&1 | grep -E "SSL certificate verify|issuer"
```

`Verify return code: 0 (ok)`는 클라이언트가 CA를 찾아 신뢰했음을 의미합니다.
