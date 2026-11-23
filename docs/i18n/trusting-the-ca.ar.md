<!-- source-sha256: 51e546526752332fcfc280e7dff9c74d662f180be9dc12f325b1f7754935dbb2 -->
# الوثوق بسلطة شهادات MiniCA

لا يقبل العميل الشهادات الصادرة عن MiniCA إلا بعد أن يثق بسلطة الشهادات (CA) التي أصدرتها. تجمع هذه الصفحة وصفات التهيئة للمنصات والأدوات الشائعة. وتنطلق كلها من التنزيلين العامَّين المتاحَين لكل سلطة شهادات (دون الحاجة إلى تسجيل الدخول):

| التنزيل | العنوان | الاستخدام |
| --- | --- | --- |
| شهادة السلطة (PEM) | `https://ca.example.com/minica/<ca-id>/download` | كل شيء عدا Java |
| مخزن الثقة للسلطة (PKCS#12، كلمة المرور `changeit`) | `https://ca.example.com/minica/download/ca/<ca-id>/truststore` | تطبيقات Java / JVM |

كلاهما مرتبط أيضًا من الفهرس العام للسلطات في `https://ca.example.com/minica/`
ومن صفحة السلطة. يُسمّى الملف باسم الاسم الشائع (common name) للسلطة، مثل
`Homelab_CA.pem`؛ وتسميه الأمثلة أدناه `minica-ca.pem` / `minica-ca.crt`.

```sh
curl -fsSLo minica-ca.pem https://ca.example.com/minica/<ca-id>/download
openssl x509 -in minica-ca.pem -noout -subject -dates -fingerprint -sha256   # check what you got
```

لا تُثبَّت على العملاء إلا **شهادة السلطة** — ولا تُثبَّت أبدًا مفتاحًا خاصًا.
إذا كانت السلطة وسيطة (intermediate)، فثبّت الشهادة الجذرية الخاصة بها بدلًا منها (أو معها).

## أنظمة التشغيل

### Debian / Ubuntu

```sh
sudo cp minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt   # must end in .crt, PEM content
sudo update-ca-certificates
```

يضيف هذا السلطة إلى `/etc/ssl/certs/ca-certificates.crt`، وهو الملف الذي تستخدمه curl وwget وPython وGo وNode (مع `NODE_EXTRA_CA_CERTS` أو `--use-openssl-ca`) وapt ومعظم البرامج الأخرى على النظام. والمجلد `/usr/local/share/ca-certificates/`
هو المكان الصحيح للإضافات المحلية؛ أما `/usr/share/ca-certificates/` فيخص
حزمة التوزيعة.

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

(نفّذ `apk add ca-certificates` أولًا إذا كان `update-ca-certificates` مفقودًا.)

### Arch Linux

```sh
sudo trust anchor --store minica-ca.pem
```

### macOS

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain minica-ca.pem
```

أو انقر نقرًا مزدوجًا على الملف، وأضفه إلى سلسلة مفاتيح *System* في Keychain Access،
ثم افتحه واضبط *When using this certificate* على *Always Trust*. يستخدم Safari
وChrome سلسلة المفاتيح؛ أما Firefox فيحتاج إلى الخطوة الإضافية أدناه.

### Windows

بصفة مسؤول (PowerShell):

```powershell
Import-Certificate -FilePath .\minica-ca.pem -CertStoreLocation Cert:\LocalMachine\Root
```

أو `certutil -addstore -f Root minica-ca.pem`، أو انقر نقرًا مزدوجًا ← *Install
Certificate* ← *Local Machine* ← *Place all certificates in the following
store* ← *Trusted Root Certification Authorities*. يستخدم Edge وChrome
و.NET/PowerShell هذا المخزن؛ أما Firefox فيحتاج إلى الخطوة الإضافية أدناه.

### Android

لا يثبّت Android إلا ملفات DER أو PEM التي يكون اسمها بامتداد `.crt`/`.cer`:

```sh
openssl x509 -in minica-ca.pem -outform DER -out minica-ca.crt
```

انسخه إلى الهاتف، ثم *Settings → Security → Encryption & credentials →
Install a certificate → CA certificate*. يحذّر Android 11 وما بعده من أن
الشهادة يجب أن تُثبَّت من الإعدادات؛ وهذا هو المسار المذكور أعلاه.
بعدها يثق بها Chrome ومعظم التطبيقات، لكن التطبيقات التي تثبّت الشهادات (pinning) أو تأتي
بمخزن الثقة الخاص بها (وبعض التطبيقات التي تستخدم حزمة الشبكة الخاصة بها) لن تثق بها.

### iOS / iPadOS

افتح ملف `.pem` على الجهاز (AirDrop أو Mail أو Files) ← *Settings → Profile
Downloaded → Install*، ثم فعّلها ضمن *Settings → General → About →
Certificate Trust Settings*.

## المتصفحات

يستخدم Chrome وEdge وSafari مخزن نظام التشغيل، لذا تكفي الخطوات المذكورة أعلاه.
أما **Firefox** فيحتفظ بمخزنه الخاص ما لم يُضبط خلاف ذلك:

- Preferences → Privacy & Security → Certificates → *View Certificates* →
  *Authorities* → *Import* → حدّد *Trust this CA to identify websites*؛ أو
- اضبط `security.enterprise_roots.enabled` على `true` في `about:config` لجعل
  Firefox يستخدم مخزن النظام في Windows / macOS؛ أو
- على Linux، استورد إلى قاعدة بيانات NSS الخاصة بالملف الشخصي:
  `certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.mozilla/firefox/<profile>` (الأداة `certutil` من الحزمة `libnss3-tools` / `nss-tools`).

يملك Chromium على Linux أيضًا مخزن NSS للسلطات التي يثبّتها المستخدم:
`certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.pki/nssdb`.

## أدوات سطر الأوامر ولغات البرمجة

### curl

```sh
curl --cacert minica-ca.pem https://intranet.example.com/
export CURL_CA_BUNDLE=/path/to/minica-ca.pem     # for a shell session
```

بعد تثبيت السلطة في مخزن النظام (أعلاه) لا حاجة إلى أي خيار.
يقوم `CURL_CA_BUNDLE` *باستبدال* الحزمة، فوجّهه إلى ملف يحتوي أيضًا
على السلطات العامة إن احتجت إلى الاثنين (مثلًا أضف ملف PEM الخاص بـ MiniCA إلى نسخة
من `/etc/ssl/certs/ca-certificates.crt`).

### wget

```sh
wget --ca-certificate=minica-ca.pem https://intranet.example.com/
echo "ca_certificate = /path/to/minica-ca.pem" >> ~/.wgetrc
```

### Python

تستخدم `urllib` و`http.client` والوحدة `ssl` المسارات الافتراضية لـ OpenSSL،
أي مخزن النظام، وتحترم `SSL_CERT_FILE` / `SSL_CERT_DIR`. أما المكتبة
`requests` (وكل ما بُني عليها، بما في ذلك `pip`) فتستخدم حزمة
`certifi` بدلًا من ذلك:

```sh
export REQUESTS_CA_BUNDLE=/path/to/minica-ca.pem   # requests; replaces the bundle
export SSL_CERT_FILE=/path/to/minica-ca.pem        # ssl / urllib / httpx
pip config set global.cert /path/to/minica-ca.pem  # pip
```

للإبقاء على السلطات العامة أيضًا، أضف ملف PEM الخاص بـ MiniCA إلى نسخة من حزمة certifi
(الأمر `python -m certifi` يطبع مسارها) ووجّه المتغيرات إلى
النسخة. أما `pip install pip-system-certs` أو `truststore` فيجعل requests تستخدم
مخزن نظام التشغيل بدلًا من ذلك.

### Java / JVM (Kafka, Elasticsearch, Jenkins, ...)

التنزيل المسمى مخزن الثقة للسلطة هو مخزن ثقة PKCS#12 جاهز للاستخدام (كلمة المرور
`changeit`، والسلطة مخزّنة بوصفها `trustedCertEntry`):

```sh
curl -fsSLo minica-truststore.p12 https://ca.example.com/minica/download/ca/<ca-id>/truststore
java -Djavax.net.ssl.trustStore=minica-truststore.p12 \
     -Djavax.net.ssl.trustStorePassword=changeit \
     -Djavax.net.ssl.trustStoreType=PKCS12 -jar app.jar
```

يحتوي مخزن الثقة هذا على سلطة MiniCA *وحدها*. ولإضافة السلطة إلى المخزن
الافتراضي في JDK بدلًا من ذلك (بحيث تبقى السلطات العامة تعمل):

```sh
keytool -importcert -trustcacerts -noprompt -alias minica \
  -file minica-ca.pem -cacerts -storepass changeit
```

تأخذ عملاء Kafka القيم `ssl.truststore.location=minica-truststore.p12`
و`ssl.truststore.password=changeit` و`ssl.truststore.type=PKCS12`.

### Go

تستخدم Go مخزن النظام (تقرأ `crypto/x509` المسار `/etc/ssl/certs` على Linux)
وتحترم `SSL_CERT_FILE` / `SSL_CERT_DIR`. ولإضافة سلطة من الشيفرة:

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

يقوم هذا *بالإضافة* إلى سلطات الشهادات المضمّنة في Node. أما `--use-openssl-ca` فيجعل Node يستخدم
مخزن النظام بدلًا من ذلك.

### yt-dlp

yt-dlp برنامج Python ويتبع قواعد Python: فإذا كانت `certifi`
مثبّتة (وهي الحالة المعتادة) فإنه يستخدم حزمتها، وإلا استخدم المخزن
الافتراضي في OpenSSL. إما أن تثبّت السلطة في مخزن النظام وتزيل certifi أو
تتجاوزها، أو توجّه حزمة HTTP في yt-dlp إلى حزمة تحتوي على الاثنين:

```sh
cat "$(python3 -m certifi)" minica-ca.pem > ~/.config/yt-dlp/ca-bundle.pem
SSL_CERT_FILE=~/.config/yt-dlp/ca-bundle.pem REQUESTS_CA_BUNDLE=~/.config/yt-dlp/ca-bundle.pem yt-dlp https://media.intranet.example.com/...
```

تجنّب `--no-check-certificates`؛ فهو يعطّل التحقق بالكامل.

## الخوادم والخدمات

### Nginx

ثلاثة أمور مختلفة يسهل الخلط بينها:

- **تقديم شهادة صادرة عن MiniCA.** نزّل *الحزمة* (Bundle، بصيغة zip) الخاصة بالشهادة — وفيها `cert.pem` و`cert.key` و`ca.pem` — واستخدم
  ```nginx
  ssl_certificate     /etc/nginx/tls/cert.pem;    # or cat cert.pem ca.pem > fullchain.pem
  ssl_certificate_key /etc/nginx/tls/cert.key;
  ```
  ثم يحتاج العملاء إلى تثبيت السلطة كما هو موضح في هذه الصفحة.
- **Nginx بوصفه عميل TLS** (عند التمرير عبر وكيل إلى خادم خلفي يقدّم
  شهادة من MiniCA):
  ```nginx
  proxy_ssl_verify on;
  proxy_ssl_trusted_certificate /etc/nginx/tls/minica-ca.pem;
  proxy_ssl_name upstream.example.com;
  ```
- **شهادات العميل (mTLS) الصادرة عن MiniCA:**
  ```nginx
  ssl_client_certificate /etc/nginx/tls/minica-ca.pem;
  ssl_verify_client on;
  ssl_crl /etc/nginx/tls/minica.crl.pem;   # optional: openssl crl -inform DER -in <crl> -out minica.crl.pem
  ```
  توجد قائمة الإلغاء (CRL) في `https://ca.example.com/minica/crl/<ca-id>` (بصيغة DER).

### Docker

بالنسبة إلى **الصورة**، أضف السلطة وقت البناء كي ترها كل أداة في الصورة:

```dockerfile
# Debian/Ubuntu based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN update-ca-certificates
# Alpine based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN apk add --no-cache ca-certificates && update-ca-certificates
```

أما بالنسبة إلى **حاوية لا يمكنك إعادة بنائها**، فاربط حزمة تحتوي بالفعل
على السلطة (مثل `/etc/ssl/certs/ca-certificates.crt` على المضيف بعد تثبيت
السلطة عليه) فوق حزمة الصورة، أو وجّه الأدوات داخلها إليها
عبر متغيرات البيئة المذكورة أعلاه:

```yaml
    environment:
      SSL_CERT_FILE:        /etc/ssl/certs/ca-certificates.crt   # OpenSSL, Python ssl, Go, Ruby
      REQUESTS_CA_BUNDLE:   /etc/ssl/certs/ca-certificates.crt   # Python requests
      CURL_CA_BUNDLE:       /etc/ssl/certs/ca-certificates.crt   # curl
      NODE_EXTRA_CA_CERTS:  /etc/ssl/certs/ca-certificates.crt   # Node.js
    volumes:
      - /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro
```

أما الصور المبنية على توزيعات تحتفظ بالحزمة في مكان آخر
(عائلة RHEL: `/etc/pki/tls/certs/ca-bundle.crt`) فتحتاج إلى ذلك المسار بدلًا منه.

يثق *خفي* Docker (daemon) بسلطة سجلٍّ خاص انطلاقًا من
`/etc/docker/certs.d/<registry:port>/ca.crt`، بصرف النظر عن مخزن النظام.

### LLDAP

LLDAP خادم: امنحه شهادة صادرة عن MiniCA لمنفذ LDAPS الخاص به
(نزّل حزمة الشهادة؛ والمفتاح هو `cert.key`):

```toml
# lldap_config.toml
[ldaps_options]
enabled = true
port = 6360
cert_file = "/data/tls/cert.pem"
key_file = "/data/tls/cert.key"
```

أو `LLDAP_LDAPS_OPTIONS__ENABLED=true` و`LLDAP_LDAPS_OPTIONS__CERT_FILE=...`
و`LLDAP_LDAPS_OPTIONS__KEY_FILE=...` في البيئة. ثم يحتاج كل عميل LDAP
(Authelia وNextcloud وJellyfin، ...) إلى سلطة MiniCA في مخزن الثقة الخاص به،
وفق الوصفات أعلاه للمنصة أو اللغة التي يعمل عليها.

## نشر MiniCA عبر Nginx

عند استخدام تسجيل الدخول المدمج في MiniCA تكفي بادئة واحدة. يحمي MiniCA صفحاته الخاصة بنفسه، ويبقى هذا الدليل متاحًا للعموم على `/minica/how-to-use`:

```nginx
location /minica/ {
    proxy_pass http://minica:9988;
    include /etc/nginx/snippets/proxy.conf;
}
```

عند استخدام SSO (مثل Authelia وoauth2-proxy) تكون البادئة محمية، لذا تحتاج الصفحات العامة إلى قاعدة خاصة بها. أبقِ ترويسات الهوية فارغة في هذه القاعدة، لأن MiniCA يثق بها عندما تصل من الوكيل:

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

## التحقق من نجاح الإعداد

```sh
openssl s_client -connect intranet.example.com:443 -servername intranet.example.com </dev/null 2>/dev/null | grep "Verify return code"
curl -v https://intranet.example.com/ 2>&1 | grep -E "SSL certificate verify|issuer"
```

تعني `Verify return code: 0 (ok)` أن العميل وجد السلطة ووثق بها.
