<!-- source-sha256: 51e546526752332fcfc280e7dff9c74d662f180be9dc12f325b1f7754935dbb2 -->
# Zaufanie do urzędu certyfikacji MiniCA

Certyfikaty wystawione przez MiniCA są akceptowane przez klienta dopiero wtedy,
gdy ten klient ufa wystawiającemu je urzędowi certyfikacji. Ta strona zbiera
przepisy dla popularnych platform i narzędzi. Wszystko zaczyna się od dwóch
publicznych plików do pobrania, które ma każde CA (logowanie nie jest potrzebne):

| Pobieranie | URL | Zastosowanie |
| --- | --- | --- |
| Certyfikat CA (PEM) | `https://ca.example.com/minica/<ca-id>/download` | wszystko oprócz Javy |
| Magazyn zaufania CA (PKCS#12, hasło `changeit`) | `https://ca.example.com/minica/download/ca/<ca-id>/truststore` | aplikacje Java / JVM |

Oba pliki są też dostępne w publicznym indeksie CA pod adresem `https://ca.example.com/minica/`
oraz na stronie CA. Plik nosi nazwę zgodną z nazwą pospolitą CA, np.
`Homelab_CA.pem`; w poniższych przykładach nazywa się `minica-ca.pem` / `minica-ca.crt`.

```sh
curl -fsSLo minica-ca.pem https://ca.example.com/minica/<ca-id>/download
openssl x509 -in minica-ca.pem -noout -subject -dates -fingerprint -sha256   # check what you got
```

Na klientach instaluje się wyłącznie **certyfikat CA** — nigdy klucz
prywatny. Jeśli CA jest pośrednie, zainstaluj zamiast niego (lub dodatkowo) jego urząd główny.

## Systemy operacyjne

### Debian / Ubuntu

```sh
sudo cp minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt   # must end in .crt, PEM content
sudo update-ca-certificates
```

Dodaje to CA do pliku `/etc/ssl/certs/ca-certificates.crt`, z którego korzystają curl, wget,
Python, Go, Node (z `NODE_EXTRA_CA_CERTS` lub `--use-openssl-ca`), apt i
większość innych programów w systemie. Katalog `/usr/local/share/ca-certificates/`
jest właściwym miejscem na lokalne dodatki; `/usr/share/ca-certificates/` należy
do pakietu dystrybucji.

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

(Najpierw wykonaj `apk add ca-certificates`, jeśli brakuje `update-ca-certificates`.)

### Arch Linux

```sh
sudo trust anchor --store minica-ca.pem
```

### macOS

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain minica-ca.pem
```

Możesz też kliknąć plik dwukrotnie, dodać go do keychaina *System* w Dostępie do pęku kluczy,
otworzyć go i ustawić *Podczas używania tego certyfikatu* na *Zawsze ufaj*. Safari i
Chrome korzystają z pęku kluczy; Firefox wymaga dodatkowego kroku opisanego poniżej.

### Windows

Jako administrator (PowerShell):

```powershell
Import-Certificate -FilePath .\minica-ca.pem -CertStoreLocation Cert:\LocalMachine\Root
```

albo `certutil -addstore -f Root minica-ca.pem`, albo kliknij dwukrotnie → *Zainstaluj
certyfikat* → *Komputer lokalny* → *Umieść wszystkie certyfikaty w następującym
magazynie* → *Zaufane główne urzędy certyfikacji*. Edge, Chrome oraz
.NET/PowerShell korzystają z tego magazynu; Firefox wymaga dodatkowego kroku opisanego poniżej.

### Android

Android instaluje tylko pliki DER lub PEM o nazwie z rozszerzeniem `.crt`/`.cer`:

```sh
openssl x509 -in minica-ca.pem -outform DER -out minica-ca.crt
```

Skopiuj plik na telefon, a następnie *Ustawienia → Zabezpieczenia → Szyfrowanie i dane logowania →
Zainstaluj certyfikat → Certyfikat CA*. Android 11+ ostrzega, że
certyfikat należy zainstalować z Ustawień; to właśnie ta ścieżka.
Chrome i większość aplikacji będzie wtedy mu ufać, ale aplikacje, które przypinają certyfikaty lub dostarczają
własny magazyn zaufania (oraz niektóre używające własnego stosu sieciowego), nie będą.

### iOS / iPadOS

Otwórz plik `.pem` na urządzeniu (AirDrop, Mail, Pliki) → *Ustawienia → Pobrany
profil → Zainstaluj*, a następnie włącz zaufanie w *Ustawienia → Ogólne → Informacje →
Ustawienia zaufania certyfikatów*.

## Przeglądarki

Chrome, Edge i Safari korzystają z magazynu systemu operacyjnego, więc powyższe kroki
wystarczą. **Firefox** ma własny magazyn, chyba że ustawisz inaczej:

- Preferencje → Prywatność i bezpieczeństwo → Certyfikaty → *Wyświetl certyfikaty* →
  *Urzędy* → *Importuj* → zaznacz *Ufaj temu CA przy identyfikacji witryn*; albo
- ustaw `security.enterprise_roots.enabled` na `true` w `about:config`, aby
  Firefox używał magazynu systemowego Windows / macOS; albo
- w Linuksie zaimportuj do bazy NSS profilu:
  `certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.mozilla/firefox/<profile>` (`certutil` z `libnss3-tools` / `nss-tools`).

Chromium w Linuksie ma również magazyn NSS dla CA instalowanych przez użytkownika:
`certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.pki/nssdb`.

## Narzędzia wiersza poleceń i języki

### curl

```sh
curl --cacert minica-ca.pem https://intranet.example.com/
export CURL_CA_BUNDLE=/path/to/minica-ca.pem     # for a shell session
```

Po zainstalowaniu CA w magazynie systemowym (powyżej) żadna opcja nie jest potrzebna.
`CURL_CA_BUNDLE` *zastępuje* pakiet, więc wskaż plik zawierający również
publiczne CA, jeśli potrzebujesz obu (np. dołącz PEM MiniCA do kopii
pliku `/etc/ssl/certs/ca-certificates.crt`).

### wget

```sh
wget --ca-certificate=minica-ca.pem https://intranet.example.com/
echo "ca_certificate = /path/to/minica-ca.pem" >> ~/.wgetrc
```

### Python

`urllib`, `http.client` i moduł `ssl` używają domyślnych ścieżek OpenSSL,
czyli magazynu systemowego, i respektują `SSL_CERT_FILE` / `SSL_CERT_DIR`. Biblioteka
`requests` (oraz wszystko, co na niej zbudowano, w tym `pip`) używa
pakietu `certifi`:

```sh
export REQUESTS_CA_BUNDLE=/path/to/minica-ca.pem   # requests; replaces the bundle
export SSL_CERT_FILE=/path/to/minica-ca.pem        # ssl / urllib / httpx
pip config set global.cert /path/to/minica-ca.pem  # pip
```

Aby zachować także publiczne CA, dołącz PEM MiniCA do kopii pakietu certifi
(`python -m certifi` wypisuje jego ścieżkę) i wskaż zmiennym tę
kopię. Polecenie `pip install pip-system-certs` lub `truststore` sprawia, że requests używa
magazynu systemu operacyjnego.

### Java / JVM (Kafka, Elasticsearch, Jenkins, ...)

Pobrany magazyn zaufania CA to gotowy do użycia magazyn zaufania PKCS#12 (hasło
`changeit`, CA zapisane jako `trustedCertEntry`):

```sh
curl -fsSLo minica-truststore.p12 https://ca.example.com/minica/download/ca/<ca-id>/truststore
java -Djavax.net.ssl.trustStore=minica-truststore.p12 \
     -Djavax.net.ssl.trustStorePassword=changeit \
     -Djavax.net.ssl.trustStoreType=PKCS12 -jar app.jar
```

Ten magazyn zaufania zawiera *wyłącznie* CA MiniCA. Aby zamiast tego dodać CA do domyślnego
magazynu JDK (aby publiczne CA nadal działały):

```sh
keytool -importcert -trustcacerts -noprompt -alias minica \
  -file minica-ca.pem -cacerts -storepass changeit
```

Klienci Kafka przyjmują `ssl.truststore.location=minica-truststore.p12`,
`ssl.truststore.password=changeit`, `ssl.truststore.type=PKCS12`.

### Go

Go używa magazynu systemowego (`crypto/x509` czyta `/etc/ssl/certs` w Linuksie) i
respektuje `SSL_CERT_FILE` / `SSL_CERT_DIR`. Aby dodać CA z poziomu kodu:

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

To *dodaje* CA do wbudowanych w Node. Opcja `--use-openssl-ca` sprawia, że Node używa
magazynu systemowego.

### yt-dlp

yt-dlp jest programem w Pythonie i podlega regułom Pythona: jeśli zainstalowano `certifi`
(zwykły przypadek), używa pakietu certifi, w przeciwnym razie domyślnego magazynu
OpenSSL. Albo zainstaluj CA w magazynie systemowym i usuń /
obejdź certifi, albo wskaż stosowi HTTP yt-dlp pakiet zawierający oba:

```sh
cat "$(python3 -m certifi)" minica-ca.pem > ~/.config/yt-dlp/ca-bundle.pem
SSL_CERT_FILE=~/.config/yt-dlp/ca-bundle.pem REQUESTS_CA_BUNDLE=~/.config/yt-dlp/ca-bundle.pem yt-dlp https://media.intranet.example.com/...
```

Unikaj `--no-check-certificates`; całkowicie wyłącza weryfikację.

## Serwery i usługi

### Nginx

Łatwo pomylić trzy różne rzeczy:

- **Udostępnianie certyfikatu wystawionego przez MiniCA.** Pobierz
  *Pakiet* certyfikatu (zip) — `cert.pem`, `cert.key` i `ca.pem` — i użyj
  ```nginx
  ssl_certificate     /etc/nginx/tls/cert.pem;    # or cat cert.pem ca.pem > fullchain.pem
  ssl_certificate_key /etc/nginx/tls/cert.key;
  ```
  Klienci muszą wtedy mieć zainstalowane CA zgodnie z opisem na tej stronie.
- **Nginx jako klient TLS** (proxy do serwera nadrzędnego, który przedstawia
  certyfikat MiniCA):
  ```nginx
  proxy_ssl_verify on;
  proxy_ssl_trusted_certificate /etc/nginx/tls/minica-ca.pem;
  proxy_ssl_name upstream.example.com;
  ```
- **Certyfikaty klienta (mTLS) wystawione przez MiniCA:**
  ```nginx
  ssl_client_certificate /etc/nginx/tls/minica-ca.pem;
  ssl_verify_client on;
  ssl_crl /etc/nginx/tls/minica.crl.pem;   # optional: openssl crl -inform DER -in <crl> -out minica.crl.pem
  ```
  CRL jest dostępna pod adresem `https://ca.example.com/minica/crl/<ca-id>` (DER).

### Docker

W przypadku **obrazu** dodaj CA podczas budowania, aby widziało je każde narzędzie w obrazie:

```dockerfile
# Debian/Ubuntu based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN update-ca-certificates
# Alpine based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN apk add --no-cache ca-certificates && update-ca-certificates
```

W przypadku **kontenera, którego nie możesz przebudować**, zamontuj pakiet już zawierający
CA (np. `/etc/ssl/certs/ca-certificates.crt` hosta po zainstalowaniu
CA na hoście) w miejsce pakietu obrazu albo wskaż narzędziom w środku ten plik
za pomocą zmiennych środowiskowych opisanych wyżej:

```yaml
    environment:
      SSL_CERT_FILE:        /etc/ssl/certs/ca-certificates.crt   # OpenSSL, Python ssl, Go, Ruby
      REQUESTS_CA_BUNDLE:   /etc/ssl/certs/ca-certificates.crt   # Python requests
      CURL_CA_BUNDLE:       /etc/ssl/certs/ca-certificates.crt   # curl
      NODE_EXTRA_CA_CERTS:  /etc/ssl/certs/ca-certificates.crt   # Node.js
    volumes:
      - /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro
```

Obrazy oparte na dystrybucjach, które trzymają pakiet gdzie indziej
(rodzina RHEL: `/etc/pki/tls/certs/ca-bundle.crt`), wymagają tamtej ścieżki.

*Demon* Dockera ufa CA prywatnego rejestru z pliku
`/etc/docker/certs.d/<registry:port>/ca.crt`, niezależnie od magazynu systemowego.

### LLDAP

LLDAP jest serwerem: nadaj mu certyfikat wystawiony przez MiniCA dla nasłuchu
LDAPS (pobierz pakiet certyfikatu; kluczem jest `cert.key`):

```toml
# lldap_config.toml
[ldaps_options]
enabled = true
port = 6360
cert_file = "/data/tls/cert.pem"
key_file = "/data/tls/cert.key"
```

albo ustaw w środowisku `LLDAP_LDAPS_OPTIONS__ENABLED=true`, `LLDAP_LDAPS_OPTIONS__CERT_FILE=...`,
`LLDAP_LDAPS_OPTIONS__KEY_FILE=...`. Każdy klient LDAP
(Authelia, Nextcloud, Jellyfin, ...) potrzebuje wtedy CA MiniCA we własnym
magazynie zaufania, zgodnie z przepisami powyżej dla platformy lub języka, na którym działa.

## Publikowanie MiniCA przez Nginx

Przy własnym logowaniu MiniCA wystarczy jeden prefiks. MiniCA sama chroni swoje prywatne strony, a ten przewodnik pozostaje publiczny pod `/minica/how-to-use`:

```nginx
location /minica/ {
    proxy_pass http://minica:9988;
    include /etc/nginx/snippets/proxy.conf;
}
```

Przy SSO (Authelia, oauth2-proxy, ...) prefiks jest chroniony, więc strony publiczne potrzebują własnej reguły. Zachowaj wyczyszczone nagłówki tożsamości w tej regule, ponieważ MiniCA im ufa, gdy pochodzą od proxy:

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

## Sprawdzanie, czy działa

```sh
openssl s_client -connect intranet.example.com:443 -servername intranet.example.com </dev/null 2>/dev/null | grep "Verify return code"
curl -v https://intranet.example.com/ 2>&1 | grep -E "SSL certificate verify|issuer"
```

`Verify return code: 0 (ok)` oznacza, że klient znalazł CA i mu zaufał.
