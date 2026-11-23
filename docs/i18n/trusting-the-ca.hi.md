<!-- source-sha256: 51e546526752332fcfc280e7dff9c74d662f180be9dc12f325b1f7754935dbb2 -->
# MiniCA सर्टिफिकेट अथॉरिटी पर भरोसा करना

MiniCA द्वारा जारी किए गए सर्टिफिकेट को क्लाइंट तभी स्वीकार करता है जब वह क्लाइंट
जारी करने वाली CA पर भरोसा करता हो। इस पेज में आम प्लेटफ़ॉर्म और टूल्स के लिए
रेसिपी दी गई हैं। सब कुछ उन दो सार्वजनिक डाउनलोड से शुरू होता है जो हर CA के
पास होते हैं (लॉगिन की ज़रूरत नहीं):

| डाउनलोड | URL | किसके लिए उपयोग करें |
| --- | --- | --- |
| CA सर्टिफिकेट (PEM) | `https://ca.example.com/minica/<ca-id>/download` | Java को छोड़कर बाकी सब कुछ |
| CA ट्रस्टस्टोर (PKCS#12, पासवर्ड `changeit`) | `https://ca.example.com/minica/download/ca/<ca-id>/truststore` | Java / JVM एप्लिकेशन |

दोनों के लिंक सार्वजनिक CA इंडेक्स `https://ca.example.com/minica/` और CA पेज पर भी
मिलते हैं। फ़ाइल का नाम CA के कॉमन नेम पर आधारित होता है, जैसे
`Homelab_CA.pem`; नीचे के उदाहरणों में इसे `minica-ca.pem` / `minica-ca.crt` कहा गया है।

```sh
curl -fsSLo minica-ca.pem https://ca.example.com/minica/<ca-id>/download
openssl x509 -in minica-ca.pem -noout -subject -dates -fingerprint -sha256   # check what you got
```

क्लाइंट पर केवल **CA सर्टिफिकेट** ही इंस्टॉल किया जाता है — प्राइवेट की कभी नहीं।
अगर CA इंटरमीडिएट है, तो उसकी जगह (या उसके साथ) उसका रूट इंस्टॉल करें।

## ऑपरेटिंग सिस्टम

### Debian / Ubuntu

```sh
sudo cp minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt   # must end in .crt, PEM content
sudo update-ca-certificates
```

इससे CA `/etc/ssl/certs/ca-certificates.crt` में जुड़ जाती है, जिसका उपयोग curl, wget,
Python, Go, Node (`NODE_EXTRA_CA_CERTS` या `--use-openssl-ca` के साथ), apt और सिस्टम
के ज़्यादातर अन्य प्रोग्राम करते हैं। `/usr/local/share/ca-certificates/`
स्थानीय जोड़ के लिए सही जगह है; `/usr/share/ca-certificates/` डिस्ट्रीब्यूशन के
पैकेज की होती है।

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

(अगर `update-ca-certificates` मौजूद न हो तो पहले `apk add ca-certificates` चलाएँ।)

### Arch Linux

```sh
sudo trust anchor --store minica-ca.pem
```

### macOS

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain minica-ca.pem
```

या फ़ाइल पर डबल-क्लिक करें, उसे Keychain Access में *System* कीचेन में जोड़ें,
उसे खोलें और *When using this certificate* को *Always Trust* पर सेट करें। Safari और
Chrome कीचेन का उपयोग करते हैं; Firefox के लिए नीचे दिया गया अतिरिक्त चरण ज़रूरी है।

### Windows

एडमिनिस्ट्रेटर के रूप में (PowerShell):

```powershell
Import-Certificate -FilePath .\minica-ca.pem -CertStoreLocation Cert:\LocalMachine\Root
```

या `certutil -addstore -f Root minica-ca.pem`, या डबल-क्लिक करें → *Install
Certificate* → *Local Machine* → *Place all certificates in the following
store* → *Trusted Root Certification Authorities*। Edge, Chrome और
.NET/PowerShell इसी स्टोर का उपयोग करते हैं; Firefox के लिए नीचे दिया गया अतिरिक्त चरण ज़रूरी है।

### Android

Android केवल `.crt`/`.cer` नाम वाली DER या PEM फ़ाइलें इंस्टॉल करता है:

```sh
openssl x509 -in minica-ca.pem -outform DER -out minica-ca.crt
```

इसे फ़ोन में कॉपी करें, फिर *Settings → Security → Encryption & credentials →
Install a certificate → CA certificate* पर जाएँ। Android 11+ चेतावनी देता है कि
सर्टिफिकेट Settings से ही इंस्टॉल किया जाना चाहिए; ऊपर बताया गया रास्ता वही है।
इसके बाद Chrome और ज़्यादातर ऐप इस पर भरोसा करते हैं, लेकिन जो ऐप सर्टिफिकेट पिन करते हैं
या अपना ट्रस्ट स्टोर साथ लाते हैं (और कुछ जो अपना नेटवर्क स्टैक इस्तेमाल करते हैं) वे नहीं करेंगे।

### iOS / iPadOS

डिवाइस पर `.pem` खोलें (AirDrop, Mail, Files) → *Settings → Profile
Downloaded → Install*, फिर इसे *Settings → General → About →
Certificate Trust Settings* में सक्षम करें।

## ब्राउज़र

Chrome, Edge और Safari ऑपरेटिंग सिस्टम के स्टोर का उपयोग करते हैं, इसलिए ऊपर के चरण
काफ़ी हैं। **Firefox** अपना अलग स्टोर रखता है, जब तक कि उसे अन्यथा न बताया जाए:

- Preferences → Privacy & Security → Certificates → *View Certificates* →
  *Authorities* → *Import* → *Trust this CA to identify websites* पर टिक करें; या
- `about:config` में `security.enterprise_roots.enabled` को `true` पर सेट करें ताकि
  Firefox Windows / macOS का सिस्टम स्टोर उपयोग करे; या
- Linux पर, प्रोफ़ाइल के NSS डेटाबेस में इंपोर्ट करें:
  `certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.mozilla/firefox/<profile>` (`certutil` `libnss3-tools` / `nss-tools` से मिलता है)।

Linux पर Chromium में भी यूज़र द्वारा इंस्टॉल की गई CA के लिए एक NSS स्टोर होता है:
`certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.pki/nssdb`।

## कमांड-लाइन टूल्स और भाषाएँ

### curl

```sh
curl --cacert minica-ca.pem https://intranet.example.com/
export CURL_CA_BUNDLE=/path/to/minica-ca.pem     # for a shell session
```

CA को सिस्टम स्टोर में इंस्टॉल करने के बाद (ऊपर देखें) किसी विकल्प की ज़रूरत नहीं होती।
`CURL_CA_BUNDLE` बंडल को *बदल देता है*, इसलिए इसे ऐसी फ़ाइल की ओर इंगित करें जिसमें
पब्लिक CA भी हों, अगर आपको दोनों चाहिए (जैसे MiniCA PEM को
`/etc/ssl/certs/ca-certificates.crt` की कॉपी में जोड़ दें)।

### wget

```sh
wget --ca-certificate=minica-ca.pem https://intranet.example.com/
echo "ca_certificate = /path/to/minica-ca.pem" >> ~/.wgetrc
```

### Python

`urllib`, `http.client` और `ssl` मॉड्यूल OpenSSL के डिफ़ॉल्ट पथों का उपयोग करते हैं,
यानी सिस्टम स्टोर, और `SSL_CERT_FILE` / `SSL_CERT_DIR` को मानते हैं।
`requests` लाइब्रेरी (और उस पर बनी हर चीज़, `pip` सहित) इसके बजाय
`certifi` बंडल का उपयोग करती है:

```sh
export REQUESTS_CA_BUNDLE=/path/to/minica-ca.pem   # requests; replaces the bundle
export SSL_CERT_FILE=/path/to/minica-ca.pem        # ssl / urllib / httpx
pip config set global.cert /path/to/minica-ca.pem  # pip
```

पब्लिक CA भी बनाए रखने के लिए, MiniCA PEM को certifi के बंडल की कॉपी में जोड़ें
(`python -m certifi` उसका पथ प्रिंट करता है) और वेरिएबल्स को उस कॉपी की ओर इंगित करें।
`pip install pip-system-certs` या `truststore` से requests ऑपरेटिंग-सिस्टम
स्टोर का उपयोग करने लगता है।

### Java / JVM (Kafka, Elasticsearch, Jenkins, ...)

CA ट्रस्टस्टोर डाउनलोड एक तैयार PKCS#12 ट्रस्टस्टोर है (पासवर्ड
`changeit`, CA को `trustedCertEntry` के रूप में संग्रहीत):

```sh
curl -fsSLo minica-truststore.p12 https://ca.example.com/minica/download/ca/<ca-id>/truststore
java -Djavax.net.ssl.trustStore=minica-truststore.p12 \
     -Djavax.net.ssl.trustStorePassword=changeit \
     -Djavax.net.ssl.trustStoreType=PKCS12 -jar app.jar
```

उस ट्रस्टस्टोर में *केवल* MiniCA की CA है। इसके बजाय CA को JDK के
डिफ़ॉल्ट स्टोर में जोड़ने के लिए (ताकि पब्लिक CA भी काम करती रहें):

```sh
keytool -importcert -trustcacerts -noprompt -alias minica \
  -file minica-ca.pem -cacerts -storepass changeit
```

Kafka क्लाइंट `ssl.truststore.location=minica-truststore.p12`,
`ssl.truststore.password=changeit`, `ssl.truststore.type=PKCS12` लेते हैं।

### Go

Go सिस्टम स्टोर का उपयोग करता है (`crypto/x509` Linux पर `/etc/ssl/certs` पढ़ता है) और
`SSL_CERT_FILE` / `SSL_CERT_DIR` को मानता है। कोड से CA जोड़ने के लिए:

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

यह Node की बंडल्ड CA में *जोड़ता है*। `--use-openssl-ca` से Node इसके बजाय
सिस्टम स्टोर का उपयोग करता है।

### yt-dlp

yt-dlp एक Python प्रोग्राम है और Python के नियमों का पालन करता है: `certifi`
इंस्टॉल होने पर (आम स्थिति) यह certifi के बंडल का उपयोग करता है, अन्यथा OpenSSL के
डिफ़ॉल्ट स्टोर का। या तो CA को सिस्टम स्टोर में इंस्टॉल करें और certifi को हटाएँ /
बायपास करें, या yt-dlp के HTTP स्टैक को ऐसे बंडल की ओर इंगित करें जिसमें दोनों हों:

```sh
cat "$(python3 -m certifi)" minica-ca.pem > ~/.config/yt-dlp/ca-bundle.pem
SSL_CERT_FILE=~/.config/yt-dlp/ca-bundle.pem REQUESTS_CA_BUNDLE=~/.config/yt-dlp/ca-bundle.pem yt-dlp https://media.intranet.example.com/...
```

`--no-check-certificates` से बचें; यह सत्यापन को पूरी तरह बंद कर देता है।

## सर्वर और सेवाएँ

### Nginx

तीन अलग-अलग बातों में आसानी से गड़बड़ हो जाती है:

- **MiniCA द्वारा जारी सर्टिफिकेट सर्व करना।** सर्टिफिकेट का
  *Bundle* (zip) डाउनलोड करें — `cert.pem`, `cert.key` और `ca.pem` — और उपयोग करें
  ```nginx
  ssl_certificate     /etc/nginx/tls/cert.pem;    # or cat cert.pem ca.pem > fullchain.pem
  ssl_certificate_key /etc/nginx/tls/cert.key;
  ```
  इसके बाद क्लाइंट्स में CA इंस्टॉल होना चाहिए, जैसा इस पेज पर बताया गया है।
- **TLS क्लाइंट के रूप में Nginx** (ऐसे अपस्ट्रीम को प्रॉक्सी करना जो
  MiniCA सर्टिफिकेट प्रस्तुत करता है):
  ```nginx
  proxy_ssl_verify on;
  proxy_ssl_trusted_certificate /etc/nginx/tls/minica-ca.pem;
  proxy_ssl_name upstream.example.com;
  ```
- **MiniCA द्वारा जारी क्लाइंट सर्टिफिकेट (mTLS):**
  ```nginx
  ssl_client_certificate /etc/nginx/tls/minica-ca.pem;
  ssl_verify_client on;
  ssl_crl /etc/nginx/tls/minica.crl.pem;   # optional: openssl crl -inform DER -in <crl> -out minica.crl.pem
  ```
  CRL `https://ca.example.com/minica/crl/<ca-id>` (DER) पर है।

### Docker

**इमेज** के लिए, CA को बिल्ड के समय जोड़ें ताकि इमेज का हर टूल उसे देख सके:

```dockerfile
# Debian/Ubuntu based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN update-ca-certificates
# Alpine based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN apk add --no-cache ca-certificates && update-ca-certificates
```

ऐसे **कंटेनर** के लिए जिसे आप रीबिल्ड नहीं कर सकते, ऐसा बंडल माउंट करें जिसमें पहले से CA हो
(जैसे होस्ट पर CA इंस्टॉल करने के बाद होस्ट की `/etc/ssl/certs/ca-certificates.crt`) और उसे इमेज के बंडल के ऊपर रखें, या
अंदर के टूल्स को ऊपर बताए गए एनवायरनमेंट वेरिएबल्स के ज़रिए उसकी ओर इंगित करें:

```yaml
    environment:
      SSL_CERT_FILE:        /etc/ssl/certs/ca-certificates.crt   # OpenSSL, Python ssl, Go, Ruby
      REQUESTS_CA_BUNDLE:   /etc/ssl/certs/ca-certificates.crt   # Python requests
      CURL_CA_BUNDLE:       /etc/ssl/certs/ca-certificates.crt   # curl
      NODE_EXTRA_CA_CERTS:  /etc/ssl/certs/ca-certificates.crt   # Node.js
    volumes:
      - /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro
```

जिन डिस्ट्रीब्यूशन पर आधारित इमेज बंडल को कहीं और रखती हैं
(RHEL-परिवार: `/etc/pki/tls/certs/ca-bundle.crt`) उनमें इसके बजाय वही पथ चाहिए।

Docker *डेमन* किसी प्राइवेट रजिस्ट्री की CA पर
`/etc/docker/certs.d/<registry:port>/ca.crt` से भरोसा करता है, जो सिस्टम स्टोर से स्वतंत्र है।

### LLDAP

LLDAP एक सर्वर है: इसके LDAPS लिसनर के लिए इसे MiniCA द्वारा जारी सर्टिफिकेट दें
(सर्टिफिकेट का बंडल डाउनलोड करें; की `cert.key` है):

```toml
# lldap_config.toml
[ldaps_options]
enabled = true
port = 6360
cert_file = "/data/tls/cert.pem"
key_file = "/data/tls/cert.key"
```

या एनवायरनमेंट में `LLDAP_LDAPS_OPTIONS__ENABLED=true`, `LLDAP_LDAPS_OPTIONS__CERT_FILE=...`,
`LLDAP_LDAPS_OPTIONS__KEY_FILE=...` दें। इसके बाद हर LDAP क्लाइंट
(Authelia, Nextcloud, Jellyfin, ...) के अपने ट्रस्ट स्टोर में MiniCA की CA होनी चाहिए,
जैसा उस प्लेटफ़ॉर्म या भाषा के लिए ऊपर की रेसिपी में बताया गया है जिस पर वह चलता है।

## Nginx के माध्यम से MiniCA प्रकाशित करना

MiniCA के अपने लॉगिन के साथ एक prefix पर्याप्त है। MiniCA अपने निजी पृष्ठों की सुरक्षा स्वयं करता है, और यह गाइड `/minica/how-to-use` पर सार्वजनिक रहती है:

```nginx
location /minica/ {
    proxy_pass http://minica:9988;
    include /etc/nginx/snippets/proxy.conf;
}
```

SSO (Authelia, oauth2-proxy आदि) के साथ prefix सुरक्षित होता है, इसलिए सार्वजनिक पृष्ठों के लिए एक अलग नियम चाहिए। उस नियम में पहचान headers को खाली रखें, क्योंकि proxy से आने पर MiniCA उन पर भरोसा करता है:

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

## जाँचना कि यह काम कर रहा है

```sh
openssl s_client -connect intranet.example.com:443 -servername intranet.example.com </dev/null 2>/dev/null | grep "Verify return code"
curl -v https://intranet.example.com/ 2>&1 | grep -E "SSL certificate verify|issuer"
```

`Verify return code: 0 (ok)` का मतलब है कि क्लाइंट को CA मिल गई और उसने उस पर भरोसा किया।
