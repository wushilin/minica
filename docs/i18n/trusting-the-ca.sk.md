<!-- source-sha256: 51e546526752332fcfc280e7dff9c74d662f180be9dc12f325b1f7754935dbb2 -->
# Dôvera voči certifikačnej autorite MiniCA

Certifikáty vydané MiniCA klient akceptuje, až keď dôveruje vydávajúcej CA.
Táto stránka zhromažďuje postupy pre bežné platformy a nástroje. Všetko
vychádza z dvoch verejných súborov na stiahnutie, ktoré má každá CA (bez
prihlásenia):

| Súbor | URL | Na čo ho použiť |
| --- | --- | --- |
| Certifikát CA (PEM) | `https://ca.example.com/minica/<ca-id>/download` | všetko okrem Javy |
| Úložisko dôveryhodných certifikátov CA (PKCS#12, heslo `changeit`) | `https://ca.example.com/minica/download/ca/<ca-id>/truststore` | aplikácie v Jave / JVM |

Obe sú odkazované aj z verejného zoznamu CA na `https://ca.example.com/minica/`
a zo stránky CA. Súbor je pomenovaný podľa bežného názvu CA, napr.
`Homelab_CA.pem`; príklady nižšie ho nazývajú `minica-ca.pem` / `minica-ca.crt`.

```sh
curl -fsSLo minica-ca.pem https://ca.example.com/minica/<ca-id>/download
openssl x509 -in minica-ca.pem -noout -subject -dates -fingerprint -sha256   # check what you got
```

Na klientov sa inštaluje vždy len **certifikát CA** — nikdy súkromný kľúč.
Ak je CA sprostredkujúca, nainštalujte namiesto nej (alebo aj s ňou) jej koreňovú CA.

## Operačné systémy

### Debian / Ubuntu

```sh
sudo cp minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt   # must end in .crt, PEM content
sudo update-ca-certificates
```

Tým sa CA pridá do `/etc/ssl/certs/ca-certificates.crt`, ktorý používajú curl,
wget, Python, Go, Node (s `NODE_EXTRA_CA_CERTS` alebo `--use-openssl-ca`), apt
a väčšina ostatných programov v systéme. `/usr/local/share/ca-certificates/`
je správne miesto pre lokálne doplnky; `/usr/share/ca-certificates/` patrí
balíku distribúcie.

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

(Ak chýba `update-ca-certificates`, najprv spustite `apk add ca-certificates`.)

### Arch Linux

```sh
sudo trust anchor --store minica-ca.pem
```

### macOS

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain minica-ca.pem
```

Alebo súbor dvakrát kliknite, pridajte ho do kľúčenky *System* v aplikácii
Keychain Access, otvorte ho a nastavte *When using this certificate* na
*Always Trust*. Safari a Chrome používajú kľúčenku; Firefox potrebuje ďalší
krok nižšie.

### Windows

Ako správca (PowerShell):

```powershell
Import-Certificate -FilePath .\minica-ca.pem -CertStoreLocation Cert:\LocalMachine\Root
```

alebo `certutil -addstore -f Root minica-ca.pem`, alebo dvojitý klik →
*Install Certificate* → *Local Machine* → *Place all certificates in the
following store* → *Trusted Root Certification Authorities*. Edge, Chrome
a .NET/PowerShell používajú toto úložisko; Firefox potrebuje ďalší krok nižšie.

### Android

Android inštaluje iba súbory DER alebo PEM s názvom `.crt`/`.cer`:

```sh
openssl x509 -in minica-ca.pem -outform DER -out minica-ca.crt
```

Skopírujte ho do telefónu a potom *Settings → Security → Encryption &
credentials → Install a certificate → CA certificate*. Android 11+ varuje,
že certifikát sa musí inštalovať z Nastavení; to je cesta uvedená vyššie.
Chrome a väčšina aplikácií mu potom dôveruje, ale aplikácie, ktoré pripínajú
certifikáty alebo majú vlastné úložisko dôvery (a niektoré s vlastným
sieťovým zásobníkom), mu dôverovať nebudú.

### iOS / iPadOS

Otvorte `.pem` na zariadení (AirDrop, Mail, Files) → *Settings → Profile
Downloaded → Install* a potom ho povoľte v *Settings → General → About →
Certificate Trust Settings*.

## Prehliadače

Chrome, Edge a Safari používajú úložisko operačného systému, takže kroky
vyššie stačia. **Firefox** má vlastné úložisko, pokiaľ sa nenastaví inak:

- Preferences → Privacy & Security → Certificates → *View Certificates* →
  *Authorities* → *Import* → zaškrtnite *Trust this CA to identify websites*; alebo
- nastavte `security.enterprise_roots.enabled` na `true` v `about:config`, aby
  Firefox používal systémové úložisko Windows / macOS; alebo
- v Linuxe importujte do databázy NSS profilu:
  `certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.mozilla/firefox/<profile>` (`certutil` z `libnss3-tools` / `nss-tools`).

Chromium v Linuxe má tiež úložisko NSS pre používateľom nainštalované CA:
`certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.pki/nssdb`.

## Nástroje príkazového riadka a jazyky

### curl

```sh
curl --cacert minica-ca.pem https://intranet.example.com/
export CURL_CA_BUNDLE=/path/to/minica-ca.pem     # for a shell session
```

Po inštalácii CA do systémového úložiska (vyššie) nie je potrebná žiadna voľba.
`CURL_CA_BUNDLE` balík *nahrádza*, preto ho nasmerujte na súbor, ktorý
obsahuje aj verejné CA, ak potrebujete oboje (napr. pripojte PEM MiniCA ku
kópii `/etc/ssl/certs/ca-certificates.crt`).

### wget

```sh
wget --ca-certificate=minica-ca.pem https://intranet.example.com/
echo "ca_certificate = /path/to/minica-ca.pem" >> ~/.wgetrc
```

### Python

`urllib`, `http.client` a modul `ssl` používajú predvolené cesty OpenSSL,
t. j. systémové úložisko, a rešpektujú `SSL_CERT_FILE` / `SSL_CERT_DIR`.
Knižnica `requests` (a všetko, čo na nej stavia, vrátane `pip`) používa
namiesto toho balík `certifi`:

```sh
export REQUESTS_CA_BUNDLE=/path/to/minica-ca.pem   # requests; replaces the bundle
export SSL_CERT_FILE=/path/to/minica-ca.pem        # ssl / urllib / httpx
pip config set global.cert /path/to/minica-ca.pem  # pip
```

Ak chcete zachovať aj verejné CA, pripojte PEM MiniCA ku kópii balíka certifi
(`python -m certifi` vypíše jeho cestu) a premenné nasmerujte na túto kópiu.
`pip install pip-system-certs` alebo `truststore` zabezpečí, že requests
použije namiesto toho úložisko operačného systému.

### Java / JVM (Kafka, Elasticsearch, Jenkins, ...)

Stiahnuté úložisko dôveryhodných certifikátov CA je hotové úložisko PKCS#12
(heslo `changeit`, CA uložená ako `trustedCertEntry`):

```sh
curl -fsSLo minica-truststore.p12 https://ca.example.com/minica/download/ca/<ca-id>/truststore
java -Djavax.net.ssl.trustStore=minica-truststore.p12 \
     -Djavax.net.ssl.trustStorePassword=changeit \
     -Djavax.net.ssl.trustStoreType=PKCS12 -jar app.jar
```

Toto úložisko obsahuje *iba* CA MiniCA. Ak chcete CA namiesto toho pridať do
predvoleného úložiska JDK (aby verejné CA naďalej fungovali):

```sh
keytool -importcert -trustcacerts -noprompt -alias minica \
  -file minica-ca.pem -cacerts -storepass changeit
```

Klienti Kafky používajú `ssl.truststore.location=minica-truststore.p12`,
`ssl.truststore.password=changeit`, `ssl.truststore.type=PKCS12`.

### Go

Go používa systémové úložisko (`crypto/x509` číta `/etc/ssl/certs` v Linuxe)
a rešpektuje `SSL_CERT_FILE` / `SSL_CERT_DIR`. Pridanie CA z kódu:

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

Toto *pridáva* k CA dodávaným s Node. `--use-openssl-ca` spôsobí, že Node
použije namiesto toho systémové úložisko.

### yt-dlp

yt-dlp je program v Pythone a riadi sa pravidlami Pythonu: ak je nainštalovaný
`certifi` (bežný prípad), použije jeho balík, inak predvolené úložisko
OpenSSL. Buď nainštalujte CA do systémového úložiska a odstráňte /
obíďte certifi, alebo nasmerujte HTTP vrstvu yt-dlp na balík, ktorý obsahuje oboje:

```sh
cat "$(python3 -m certifi)" minica-ca.pem > ~/.config/yt-dlp/ca-bundle.pem
SSL_CERT_FILE=~/.config/yt-dlp/ca-bundle.pem REQUESTS_CA_BUNDLE=~/.config/yt-dlp/ca-bundle.pem yt-dlp https://media.intranet.example.com/...
```

Nepoužívajte `--no-check-certificates`; úplne vypína overovanie.

## Servery a služby

### Nginx

Ľahko sa zamenia tri rôzne veci:

- **Poskytovanie certifikátu vydaného MiniCA.** Stiahnite *Bundle* (zip)
  certifikátu — `cert.pem`, `cert.key` a `ca.pem` — a použite
  ```nginx
  ssl_certificate     /etc/nginx/tls/cert.pem;    # or cat cert.pem ca.pem > fullchain.pem
  ssl_certificate_key /etc/nginx/tls/cert.key;
  ```
  Klienti potom potrebujú nainštalovanú CA podľa tejto stránky.
- **Nginx ako klient TLS** (proxy na upstream, ktorý predkladá
  certifikát MiniCA):
  ```nginx
  proxy_ssl_verify on;
  proxy_ssl_trusted_certificate /etc/nginx/tls/minica-ca.pem;
  proxy_ssl_name upstream.example.com;
  ```
- **Klientske certifikáty (mTLS) vydané MiniCA:**
  ```nginx
  ssl_client_certificate /etc/nginx/tls/minica-ca.pem;
  ssl_verify_client on;
  ssl_crl /etc/nginx/tls/minica.crl.pem;   # optional: openssl crl -inform DER -in <crl> -out minica.crl.pem
  ```
  CRL je na `https://ca.example.com/minica/crl/<ca-id>` (DER).

### Docker

Pri **image** pridajte CA pri zostavovaní, aby ju videl každý nástroj v image:

```dockerfile
# Debian/Ubuntu based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN update-ca-certificates
# Alpine based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN apk add --no-cache ca-certificates && update-ca-certificates
```

Pri **kontajneri, ktorý nemôžete znovu zostaviť**, pripojte balík, ktorý už
obsahuje CA (napr. `/etc/ssl/certs/ca-certificates.crt` hostiteľa po
inštalácii CA na hostiteľovi) namiesto balíka z image, alebo nasmerujte nástroje
vnútri naň pomocou vyššie uvedených premenných prostredia:

```yaml
    environment:
      SSL_CERT_FILE:        /etc/ssl/certs/ca-certificates.crt   # OpenSSL, Python ssl, Go, Ruby
      REQUESTS_CA_BUNDLE:   /etc/ssl/certs/ca-certificates.crt   # Python requests
      CURL_CA_BUNDLE:       /etc/ssl/certs/ca-certificates.crt   # curl
      NODE_EXTRA_CA_CERTS:  /etc/ssl/certs/ca-certificates.crt   # Node.js
    volumes:
      - /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro
```

Image založené na distribúciách, ktoré majú balík inde
(rodina RHEL: `/etc/pki/tls/certs/ca-bundle.crt`), potrebujú namiesto toho túto cestu.

*Démon* Dockera dôveruje CA súkromného registra z
`/etc/docker/certs.d/<registry:port>/ca.crt`, nezávisle od systémového úložiska.

### LLDAP

LLDAP je server: dajte mu certifikát vydaný MiniCA pre jeho listener LDAPS
(stiahnite balík certifikátu; kľúč je `cert.key`):

```toml
# lldap_config.toml
[ldaps_options]
enabled = true
port = 6360
cert_file = "/data/tls/cert.pem"
key_file = "/data/tls/cert.key"
```

alebo `LLDAP_LDAPS_OPTIONS__ENABLED=true`, `LLDAP_LDAPS_OPTIONS__CERT_FILE=...`,
`LLDAP_LDAPS_OPTIONS__KEY_FILE=...` v prostredí. Každý klient LDAP
(Authelia, Nextcloud, Jellyfin, ...) potom potrebuje CA MiniCA vo vlastnom
úložisku dôvery podľa vyššie uvedených postupov pre platformu alebo jazyk, v ktorom beží.

## Zverejnenie MiniCA cez Nginx

S vlastným prihlásením MiniCA stačí jeden prefix. MiniCA chráni svoje súkromné stránky sama a táto príručka zostáva verejná na `/minica/how-to-use`:

```nginx
location /minica/ {
    proxy_pass http://minica:9988;
    include /etc/nginx/snippets/proxy.conf;
}
```

Pri SSO (Authelia, oauth2-proxy, ...) je prefix chránený, takže verejné stránky potrebujú vlastné pravidlo. Na tomto pravidle ponechajte hlavičky identity vyčistené, pretože MiniCA im dôveruje, keď prichádzajú z proxy:

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

## Overenie, že to funguje

```sh
openssl s_client -connect intranet.example.com:443 -servername intranet.example.com </dev/null 2>/dev/null | grep "Verify return code"
curl -v https://intranet.example.com/ 2>&1 | grep -E "SSL certificate verify|issuer"
```

`Verify return code: 0 (ok)` znamená, že klient CA našiel a dôveruje jej.
