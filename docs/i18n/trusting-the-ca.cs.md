<!-- source-sha256: 51e546526752332fcfc280e7dff9c74d662f180be9dc12f325b1f7754935dbb2 -->
# Důvěra v certifikační autoritu MiniCA

Certifikáty vydané MiniCA klient přijme teprve tehdy, když důvěřuje vydávající
CA. Tato stránka shrnuje postupy pro běžné platformy a nástroje. Vše vychází
ze dvou veřejných souborů ke stažení, které má každá CA (není třeba přihlášení):

| Stažení | URL | K čemu slouží |
| --- | --- | --- |
| Certifikát CA (PEM) | `https://ca.example.com/minica/<ca-id>/download` | vše kromě Javy |
| Úložiště důvěryhodných certifikátů CA (PKCS#12, heslo `changeit`) | `https://ca.example.com/minica/download/ca/<ca-id>/truststore` | aplikace v Javě / JVM |

Oba soubory jsou také odkazovány z veřejného indexu CA na
`https://ca.example.com/minica/` a ze stránky CA. Soubor je pojmenován podle
běžného názvu CA, např. `Homelab_CA.pem`; níže uvedené příklady ho nazývají
`minica-ca.pem` / `minica-ca.crt`.

```sh
curl -fsSLo minica-ca.pem https://ca.example.com/minica/<ca-id>/download
openssl x509 -in minica-ca.pem -noout -subject -dates -fingerprint -sha256   # check what you got
```

Na klienty se instaluje vždy pouze **certifikát CA** — nikdy soukromý klíč.
Pokud je CA zprostředkující, nainstalujte místo ní (nebo i ji) kořenovou CA.

## Operační systémy

### Debian / Ubuntu

```sh
sudo cp minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt   # must end in .crt, PEM content
sudo update-ca-certificates
```

Tím se CA přidá do `/etc/ssl/certs/ca-certificates.crt`, který používají curl,
wget, Python, Go, Node (s `NODE_EXTRA_CA_CERTS` nebo `--use-openssl-ca`), apt
a většina dalších programů v systému. `/usr/local/share/ca-certificates/`
je správné místo pro lokální doplňky; `/usr/share/ca-certificates/` patří
balíčku distribuce.

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

(Pokud chybí `update-ca-certificates`, nejprve spusťte `apk add ca-certificates`.)

### Arch Linux

```sh
sudo trust anchor --store minica-ca.pem
```

### macOS

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain minica-ca.pem
```

Nebo na soubor dvakrát klikněte, přidejte ho do klíčenky *System* v aplikaci
Keychain Access, otevřete ho a nastavte *When using this certificate* na
*Always Trust*. Safari a Chrome používají klíčenku; Firefox potřebuje
dodatečný krok níže.

### Windows

Jako administrátor (PowerShell):

```powershell
Import-Certificate -FilePath .\minica-ca.pem -CertStoreLocation Cert:\LocalMachine\Root
```

nebo `certutil -addstore -f Root minica-ca.pem`, nebo dvojklik → *Install
Certificate* → *Local Machine* → *Place all certificates in the following
store* → *Trusted Root Certification Authorities*. Edge, Chrome a
.NET/PowerShell toto úložiště používají; Firefox potřebuje dodatečný krok níže.

### Android

Android instaluje pouze soubory DER nebo PEM s příponou `.crt`/`.cer`:

```sh
openssl x509 -in minica-ca.pem -outform DER -out minica-ca.crt
```

Zkopírujte soubor do telefonu a poté *Settings → Security → Encryption & credentials →
Install a certificate → CA certificate*. Android 11+ upozorňuje, že
certifikát musí být nainstalován z Nastavení; to je výše uvedená cesta.
Chrome a většina aplikací mu pak bude důvěřovat, ale aplikace, které připínají
certifikáty nebo mají vlastní úložiště důvěryhodných certifikátů (a některé,
které používají vlastní síťový zásobník), ne.

### iOS / iPadOS

Otevřete `.pem` v zařízení (AirDrop, Mail, Files) → *Settings → Profile
Downloaded → Install* a poté ho povolte v *Settings → General → About →
Certificate Trust Settings*.

## Prohlížeče

Chrome, Edge a Safari používají úložiště operačního systému, takže výše
uvedené kroky stačí. **Firefox** má vlastní úložiště, pokud mu nenařídíte jinak:

- Preferences → Privacy & Security → Certificates → *View Certificates* →
  *Authorities* → *Import* → zaškrtněte *Trust this CA to identify websites*; nebo
- nastavte `security.enterprise_roots.enabled` na `true` v `about:config`, aby
  Firefox používal systémové úložiště Windows / macOS; nebo
- v Linuxu importujte do databáze NSS profilu:
  `certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.mozilla/firefox/<profile>` (`certutil` z `libnss3-tools` / `nss-tools`).

Chromium v Linuxu má také úložiště NSS pro uživatelem nainstalované CA:
`certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.pki/nssdb`.

## Nástroje příkazové řádky a programovací jazyky

### curl

```sh
curl --cacert minica-ca.pem https://intranet.example.com/
export CURL_CA_BUNDLE=/path/to/minica-ca.pem     # for a shell session
```

Po instalaci CA do systémového úložiště (viz výše) není žádná volba potřeba.
`CURL_CA_BUNDLE` balíček *nahrazuje*, takže ho nasměrujte na soubor, který
obsahuje i veřejné CA, pokud potřebujete obojí (např. připojte PEM MiniCA ke kopii
souboru `/etc/ssl/certs/ca-certificates.crt`).

### wget

```sh
wget --ca-certificate=minica-ca.pem https://intranet.example.com/
echo "ca_certificate = /path/to/minica-ca.pem" >> ~/.wgetrc
```

### Python

`urllib`, `http.client` a modul `ssl` používají výchozí cesty OpenSSL,
tj. systémové úložiště, a respektují `SSL_CERT_FILE` / `SSL_CERT_DIR`. Knihovna
`requests` (a vše, co na ní stojí, včetně `pip`) místo toho používá
balíček `certifi`:

```sh
export REQUESTS_CA_BUNDLE=/path/to/minica-ca.pem   # requests; replaces the bundle
export SSL_CERT_FILE=/path/to/minica-ca.pem        # ssl / urllib / httpx
pip config set global.cert /path/to/minica-ca.pem  # pip
```

Chcete-li zachovat i veřejné CA, připojte PEM MiniCA ke kopii balíčku certifi
(`python -m certifi` vypíše jeho cestu) a proměnné nasměrujte na tuto
kopii. `pip install pip-system-certs` nebo `truststore` způsobí, že requests
bude místo toho používat úložiště operačního systému.

### Java / JVM (Kafka, Elasticsearch, Jenkins, ...)

Stažené úložiště důvěryhodných certifikátů CA je hotové úložiště PKCS#12 (heslo
`changeit`, CA uložená jako `trustedCertEntry`):

```sh
curl -fsSLo minica-truststore.p12 https://ca.example.com/minica/download/ca/<ca-id>/truststore
java -Djavax.net.ssl.trustStore=minica-truststore.p12 \
     -Djavax.net.ssl.trustStorePassword=changeit \
     -Djavax.net.ssl.trustStoreType=PKCS12 -jar app.jar
```

Toto úložiště obsahuje *pouze* CA MiniCA. Chcete-li CA přidat do výchozího
úložiště JDK (aby veřejné CA nadále fungovaly):

```sh
keytool -importcert -trustcacerts -noprompt -alias minica \
  -file minica-ca.pem -cacerts -storepass changeit
```

Klienti Kafka používají `ssl.truststore.location=minica-truststore.p12`,
`ssl.truststore.password=changeit`, `ssl.truststore.type=PKCS12`.

### Go

Go používá systémové úložiště (`crypto/x509` čte `/etc/ssl/certs` v Linuxu)
a respektuje `SSL_CERT_FILE` / `SSL_CERT_DIR`. Přidání CA z kódu:

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

Tím se CA *přidají* k CA dodávaným s Node. `--use-openssl-ca` způsobí, že Node
použije místo toho systémové úložiště.

### yt-dlp

yt-dlp je program v Pythonu a řídí se pravidly Pythonu: pokud je nainstalován
`certifi` (obvyklý případ), použije jeho balíček, jinak výchozí úložiště
OpenSSL. Buď nainstalujte CA do systémového úložiště a odstraňte /
obejděte certifi, nebo nasměrujte HTTP vrstvu yt-dlp na balíček, který obsahuje obojí:

```sh
cat "$(python3 -m certifi)" minica-ca.pem > ~/.config/yt-dlp/ca-bundle.pem
SSL_CERT_FILE=~/.config/yt-dlp/ca-bundle.pem REQUESTS_CA_BUNDLE=~/.config/yt-dlp/ca-bundle.pem yt-dlp https://media.intranet.example.com/...
```

Nepoužívejte `--no-check-certificates`; úplně vypíná ověřování.

## Servery a služby

### Nginx

Snadno se pletou tři různé věci:

- **Poskytování certifikátu vydaného MiniCA.** Stáhněte *Bundle* (zip)
  certifikátu — `cert.pem`, `cert.key` a `ca.pem` — a použijte
  ```nginx
  ssl_certificate     /etc/nginx/tls/cert.pem;    # or cat cert.pem ca.pem > fullchain.pem
  ssl_certificate_key /etc/nginx/tls/cert.key;
  ```
  Klienti pak potřebují mít CA nainstalovanou podle popisu na této stránce.
- **Nginx jako TLS klient** (proxy k upstreamu, který předkládá
  certifikát MiniCA):
  ```nginx
  proxy_ssl_verify on;
  proxy_ssl_trusted_certificate /etc/nginx/tls/minica-ca.pem;
  proxy_ssl_name upstream.example.com;
  ```
- **Klientské certifikáty (mTLS) vydané MiniCA:**
  ```nginx
  ssl_client_certificate /etc/nginx/tls/minica-ca.pem;
  ssl_verify_client on;
  ssl_crl /etc/nginx/tls/minica.crl.pem;   # optional: openssl crl -inform DER -in <crl> -out minica.crl.pem
  ```
  CRL je na `https://ca.example.com/minica/crl/<ca-id>` (DER).

### Docker

U **image** přidejte CA při sestavování, aby ji viděl každý nástroj v image:

```dockerfile
# Debian/Ubuntu based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN update-ca-certificates
# Alpine based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN apk add --no-cache ca-certificates && update-ca-certificates
```

U **kontejneru, který nemůžete znovu sestavit**, připojte balíček, který už
CA obsahuje (např. `/etc/ssl/certs/ca-certificates.crt` hostitele po instalaci
CA na hostiteli), přes balíček v image, nebo na něj nasměrujte nástroje uvnitř
pomocí výše uvedených proměnných prostředí:

```yaml
    environment:
      SSL_CERT_FILE:        /etc/ssl/certs/ca-certificates.crt   # OpenSSL, Python ssl, Go, Ruby
      REQUESTS_CA_BUNDLE:   /etc/ssl/certs/ca-certificates.crt   # Python requests
      CURL_CA_BUNDLE:       /etc/ssl/certs/ca-certificates.crt   # curl
      NODE_EXTRA_CA_CERTS:  /etc/ssl/certs/ca-certificates.crt   # Node.js
    volumes:
      - /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro
```

Image založené na distribucích, které mají balíček jinde
(rodina RHEL: `/etc/pki/tls/certs/ca-bundle.crt`), potřebují místo toho tuto cestu.

*Démon* Dockeru důvěřuje CA soukromého registru z
`/etc/docker/certs.d/<registry:port>/ca.crt`, nezávisle na systémovém úložišti.

### LLDAP

LLDAP je server: dejte mu certifikát vydaný MiniCA pro jeho naslouchání LDAPS
(stáhněte balíček certifikátu; klíč je `cert.key`):

```toml
# lldap_config.toml
[ldaps_options]
enabled = true
port = 6360
cert_file = "/data/tls/cert.pem"
key_file = "/data/tls/cert.key"
```

nebo `LLDAP_LDAPS_OPTIONS__ENABLED=true`, `LLDAP_LDAPS_OPTIONS__CERT_FILE=...`,
`LLDAP_LDAPS_OPTIONS__KEY_FILE=...` v prostředí. Každý klient LDAP
(Authelia, Nextcloud, Jellyfin, ...) pak potřebuje CA MiniCA ve vlastním
úložišti důvěryhodných certifikátů, podle výše uvedených postupů pro platformu nebo jazyk, na kterém běží.

## Zveřejnění MiniCA přes Nginx

S vlastním přihlášením MiniCA stačí jeden prefix. MiniCA své soukromé stránky chrání sama a tento návod zůstává veřejný na `/minica/how-to-use`:

```nginx
location /minica/ {
    proxy_pass http://minica:9988;
    include /etc/nginx/snippets/proxy.conf;
}
```

U SSO (Authelia, oauth2-proxy, ...) je prefix chráněn, takže veřejné stránky potřebují vlastní pravidlo. Na tomto pravidle ponechte hlavičky identity vymazané, protože MiniCA jim důvěřuje, pokud přicházejí od proxy:

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

## Ověření, že vše funguje

```sh
openssl s_client -connect intranet.example.com:443 -servername intranet.example.com </dev/null 2>/dev/null | grep "Verify return code"
curl -v https://intranet.example.com/ 2>&1 | grep -E "SSL certificate verify|issuer"
```

`Verify return code: 0 (ok)` znamená, že klient CA našel a důvěřuje jí.
