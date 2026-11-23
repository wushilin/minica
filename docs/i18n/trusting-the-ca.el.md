<!-- source-sha256: 51e546526752332fcfc280e7dff9c74d662f180be9dc12f325b1f7754935dbb2 -->
# Εμπιστοσύνη σε μια αρχή πιστοποίησης MiniCA

Τα πιστοποιητικά που εκδίδει το MiniCA γίνονται δεκτά από έναν πελάτη μόνο
όταν ο πελάτης αυτός εμπιστεύεται την εκδούσα CA. Αυτή η σελίδα συγκεντρώνει
τις συνταγές για τις συνηθισμένες πλατφόρμες και εργαλεία. Όλα ξεκινούν από
τις δύο δημόσιες λήψεις που διαθέτει κάθε CA (δεν απαιτείται σύνδεση):

| Λήψη | URL | Χρήση για |
| --- | --- | --- |
| Πιστοποιητικό CA (PEM) | `https://ca.example.com/minica/<ca-id>/download` | τα πάντα εκτός από Java |
| Truststore CA (PKCS#12, κωδικός `changeit`) | `https://ca.example.com/minica/download/ca/<ca-id>/truststore` | εφαρμογές Java / JVM |

Και τα δύο συνδέονται επίσης από το δημόσιο ευρετήριο CA στο `https://ca.example.com/minica/`
και από τη σελίδα της CA. Το αρχείο φέρει το κοινό όνομα της CA, π.χ.
`Homelab_CA.pem`· τα παραδείγματα παρακάτω το αναφέρουν ως `minica-ca.pem` / `minica-ca.crt`.

```sh
curl -fsSLo minica-ca.pem https://ca.example.com/minica/<ca-id>/download
openssl x509 -in minica-ca.pem -noout -subject -dates -fingerprint -sha256   # check what you got
```

Στους πελάτες εγκαθίσταται πάντοτε μόνο το **πιστοποιητικό της CA** — ποτέ
ιδιωτικό κλειδί. Αν η CA είναι ενδιάμεση, εγκαταστήστε αντί γι' αυτήν τη ρίζα της (ή και τις δύο).

## Λειτουργικά συστήματα

### Debian / Ubuntu

```sh
sudo cp minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt   # must end in .crt, PEM content
sudo update-ca-certificates
```

Αυτό προσθέτει την CA στο `/etc/ssl/certs/ca-certificates.crt`, το οποίο
χρησιμοποιούν τα curl, wget, Python, Go, Node (με `NODE_EXTRA_CA_CERTS` ή `--use-openssl-ca`), apt και
τα περισσότερα άλλα προγράμματα του συστήματος. Το `/usr/local/share/ca-certificates/`
είναι το σωστό μέρος για τοπικές προσθήκες· το `/usr/share/ca-certificates/` ανήκει
στο πακέτο της διανομής.

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

(Εκτελέστε πρώτα `apk add ca-certificates` αν λείπει το `update-ca-certificates`.)

### Arch Linux

```sh
sudo trust anchor --store minica-ca.pem
```

### macOS

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain minica-ca.pem
```

Ή κάντε διπλό κλικ στο αρχείο, προσθέστε το στην κλειδοθήκη *System* στην Πρόσβαση Κλειδοθήκης,
ανοίξτε το και ορίστε το *When using this certificate* σε *Always Trust*. Το Safari και
το Chrome χρησιμοποιούν την κλειδοθήκη· το Firefox χρειάζεται το πρόσθετο βήμα παρακάτω.

### Windows

Ως διαχειριστής (PowerShell):

```powershell
Import-Certificate -FilePath .\minica-ca.pem -CertStoreLocation Cert:\LocalMachine\Root
```

ή `certutil -addstore -f Root minica-ca.pem`, ή διπλό κλικ → *Install
Certificate* → *Local Machine* → *Place all certificates in the following
store* → *Trusted Root Certification Authorities*. Τα Edge, Chrome και
.NET/PowerShell χρησιμοποιούν αυτό το χώρο αποθήκευσης· το Firefox χρειάζεται το πρόσθετο βήμα παρακάτω.

### Android

Το Android εγκαθιστά μόνο αρχεία DER ή PEM με όνομα `.crt`/`.cer`:

```sh
openssl x509 -in minica-ca.pem -outform DER -out minica-ca.crt
```

Αντιγράψτε το στο τηλέφωνο και μετά *Settings → Security → Encryption & credentials →
Install a certificate → CA certificate*. Το Android 11+ προειδοποιεί ότι το
πιστοποιητικό πρέπει να εγκατασταθεί από τις Ρυθμίσεις· αυτή είναι η παραπάνω διαδρομή.
Το Chrome και οι περισσότερες εφαρμογές το εμπιστεύονται στη συνέχεια, αλλά εφαρμογές που καρφιτσώνουν πιστοποιητικά (pinning) ή περιλαμβάνουν
δικό τους χώρο εμπιστοσύνης (και ορισμένες που χρησιμοποιούν δική τους στοίβα δικτύου) δεν θα το κάνουν.

### iOS / iPadOS

Ανοίξτε το `.pem` στη συσκευή (AirDrop, Mail, Files) → *Settings → Profile
Downloaded → Install* και μετά ενεργοποιήστε το στο *Settings → General → About →
Certificate Trust Settings*.

## Προγράμματα περιήγησης

Τα Chrome, Edge και Safari χρησιμοποιούν τον χώρο αποθήκευσης του λειτουργικού συστήματος, οπότε τα παραπάνω βήματα
αρκούν. Το **Firefox** διατηρεί δικό του χώρο αποθήκευσης, εκτός αν οριστεί διαφορετικά:

- Preferences → Privacy & Security → Certificates → *View Certificates* →
  *Authorities* → *Import* → επιλέξτε *Trust this CA to identify websites*· ή
- ορίστε το `security.enterprise_roots.enabled` σε `true` στο `about:config` ώστε το
  Firefox να χρησιμοποιεί τον χώρο αποθήκευσης συστήματος των Windows / macOS· ή
- σε Linux, εισαγάγετε στη βάση NSS του προφίλ:
  `certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.mozilla/firefox/<profile>` (το `certutil` από `libnss3-tools` / `nss-tools`).

Το Chromium σε Linux διαθέτει επίσης χώρο NSS για CA που εγκαθιστά ο χρήστης:
`certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.pki/nssdb`.

## Εργαλεία γραμμής εντολών και γλώσσες

### curl

```sh
curl --cacert minica-ca.pem https://intranet.example.com/
export CURL_CA_BUNDLE=/path/to/minica-ca.pem     # for a shell session
```

Μετά την εγκατάσταση της CA στον χώρο αποθήκευσης συστήματος (παραπάνω) δεν χρειάζεται καμία επιλογή.
Το `CURL_CA_BUNDLE` *αντικαθιστά* το πακέτο, οπότε υποδείξτε ένα αρχείο που περιέχει επίσης
τις δημόσιες CA αν χρειάζεστε και τα δύο (π.χ. προσθέστε το PEM του MiniCA σε ένα αντίγραφο
του `/etc/ssl/certs/ca-certificates.crt`).

### wget

```sh
wget --ca-certificate=minica-ca.pem https://intranet.example.com/
echo "ca_certificate = /path/to/minica-ca.pem" >> ~/.wgetrc
```

### Python

Τα `urllib`, `http.client` και το άρθρωμα `ssl` χρησιμοποιούν τις προεπιλεγμένες διαδρομές του OpenSSL,
δηλαδή τον χώρο αποθήκευσης συστήματος, και σέβονται τα `SSL_CERT_FILE` / `SSL_CERT_DIR`. Η
βιβλιοθήκη `requests` (και ό,τι βασίζεται σε αυτήν, συμπεριλαμβανομένου του `pip`) χρησιμοποιεί αντίθετα το
πακέτο `certifi`:

```sh
export REQUESTS_CA_BUNDLE=/path/to/minica-ca.pem   # requests; replaces the bundle
export SSL_CERT_FILE=/path/to/minica-ca.pem        # ssl / urllib / httpx
pip config set global.cert /path/to/minica-ca.pem  # pip
```

Για να διατηρήσετε και τις δημόσιες CA, προσθέστε το PEM του MiniCA σε ένα αντίγραφο του πακέτου του certifi
(το `python -m certifi` εκτυπώνει τη διαδρομή του) και υποδείξτε το αντίγραφο στις μεταβλητές.
Η εντολή `pip install pip-system-certs` ή το `truststore` κάνει το requests να χρησιμοποιεί
τον χώρο αποθήκευσης του λειτουργικού συστήματος.

### Java / JVM (Kafka, Elasticsearch, Jenkins, ...)

Η λήψη του truststore της CA είναι ένα έτοιμο προς χρήση truststore PKCS#12 (κωδικός
`changeit`, με την CA αποθηκευμένη ως `trustedCertEntry`):

```sh
curl -fsSLo minica-truststore.p12 https://ca.example.com/minica/download/ca/<ca-id>/truststore
java -Djavax.net.ssl.trustStore=minica-truststore.p12 \
     -Djavax.net.ssl.trustStorePassword=changeit \
     -Djavax.net.ssl.trustStoreType=PKCS12 -jar app.jar
```

Αυτό το truststore περιέχει *μόνο* την CA του MiniCA. Για να προσθέσετε την CA στον
προεπιλεγμένο χώρο αποθήκευσης του JDK (ώστε να συνεχίσουν να λειτουργούν οι δημόσιες CA):

```sh
keytool -importcert -trustcacerts -noprompt -alias minica \
  -file minica-ca.pem -cacerts -storepass changeit
```

Οι πελάτες Kafka δέχονται `ssl.truststore.location=minica-truststore.p12`,
`ssl.truststore.password=changeit`, `ssl.truststore.type=PKCS12`.

### Go

Η Go χρησιμοποιεί τον χώρο αποθήκευσης συστήματος (το `crypto/x509` διαβάζει το `/etc/ssl/certs` σε Linux) και
σέβεται τα `SSL_CERT_FILE` / `SSL_CERT_DIR`. Για να προσθέσετε μια CA από κώδικα:

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

Αυτό *προσθέτει* στις ενσωματωμένες CA του Node. Το `--use-openssl-ca` κάνει το Node να χρησιμοποιεί
τον χώρο αποθήκευσης συστήματος.

### yt-dlp

Το yt-dlp είναι πρόγραμμα Python και ακολουθεί τους κανόνες της Python: με εγκατεστημένο το `certifi`
(η συνηθισμένη περίπτωση) χρησιμοποιεί το πακέτο του certifi, αλλιώς τον προεπιλεγμένο
χώρο αποθήκευσης του OpenSSL. Είτε εγκαταστήστε την CA στον χώρο αποθήκευσης συστήματος και αφαιρέστε /
παρακάμψτε το certifi, είτε υποδείξτε στη στοίβα HTTP του yt-dlp ένα πακέτο που περιέχει και τα δύο:

```sh
cat "$(python3 -m certifi)" minica-ca.pem > ~/.config/yt-dlp/ca-bundle.pem
SSL_CERT_FILE=~/.config/yt-dlp/ca-bundle.pem REQUESTS_CA_BUNDLE=~/.config/yt-dlp/ca-bundle.pem yt-dlp https://media.intranet.example.com/...
```

Αποφύγετε το `--no-check-certificates`· απενεργοποιεί εντελώς την επαλήθευση.

## Διακομιστές και υπηρεσίες

### Nginx

Τρία διαφορετικά πράγματα μπερδεύονται εύκολα:

- **Σερβίρισμα πιστοποιητικού που εξέδωσε το MiniCA.** Κατεβάστε το *Bundle* (zip)
  του πιστοποιητικού — `cert.pem`, `cert.key` και `ca.pem` — και χρησιμοποιήστε
  ```nginx
  ssl_certificate     /etc/nginx/tls/cert.pem;    # or cat cert.pem ca.pem > fullchain.pem
  ssl_certificate_key /etc/nginx/tls/cert.key;
  ```
  Οι πελάτες χρειάζονται τότε την CA εγκατεστημένη όπως περιγράφεται σε αυτή τη σελίδα.
- **Nginx ως πελάτης TLS** (προώθηση σε upstream που παρουσιάζει
  πιστοποιητικό MiniCA):
  ```nginx
  proxy_ssl_verify on;
  proxy_ssl_trusted_certificate /etc/nginx/tls/minica-ca.pem;
  proxy_ssl_name upstream.example.com;
  ```
- **Πιστοποιητικά πελάτη (mTLS) που εκδίδει το MiniCA:**
  ```nginx
  ssl_client_certificate /etc/nginx/tls/minica-ca.pem;
  ssl_verify_client on;
  ssl_crl /etc/nginx/tls/minica.crl.pem;   # optional: openssl crl -inform DER -in <crl> -out minica.crl.pem
  ```
  Η CRL βρίσκεται στο `https://ca.example.com/minica/crl/<ca-id>` (DER).

### Docker

Για μια **εικόνα**, προσθέστε την CA κατά το build ώστε κάθε εργαλείο στην εικόνα να τη βλέπει:

```dockerfile
# Debian/Ubuntu based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN update-ca-certificates
# Alpine based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN apk add --no-cache ca-certificates && update-ca-certificates
```

Για ένα **container που δεν μπορείτε να ξαναχτίσετε**, προσαρτήστε ένα πακέτο που περιέχει ήδη
την CA (π.χ. το `/etc/ssl/certs/ca-certificates.crt` του host μετά την εγκατάσταση
της CA στον host) πάνω από το πακέτο της εικόνας, ή υποδείξτε το στα εργαλεία μέσα στο container
μέσω των μεταβλητών περιβάλλοντος παραπάνω:

```yaml
    environment:
      SSL_CERT_FILE:        /etc/ssl/certs/ca-certificates.crt   # OpenSSL, Python ssl, Go, Ruby
      REQUESTS_CA_BUNDLE:   /etc/ssl/certs/ca-certificates.crt   # Python requests
      CURL_CA_BUNDLE:       /etc/ssl/certs/ca-certificates.crt   # curl
      NODE_EXTRA_CA_CERTS:  /etc/ssl/certs/ca-certificates.crt   # Node.js
    volumes:
      - /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro
```

Οι εικόνες που βασίζονται σε διανομές οι οποίες κρατούν το πακέτο αλλού
(οικογένεια RHEL: `/etc/pki/tls/certs/ca-bundle.crt`) χρειάζονται εκείνη τη διαδρομή.

Ο *daemon* του Docker εμπιστεύεται την CA ενός ιδιωτικού registry από το
`/etc/docker/certs.d/<registry:port>/ca.crt`, ανεξάρτητα από τον χώρο αποθήκευσης συστήματος.

### LLDAP

Το LLDAP είναι διακομιστής: δώστε του ένα πιστοποιητικό που εξέδωσε το MiniCA για τον
δέκτη LDAPS (κατεβάστε το bundle του πιστοποιητικού· το κλειδί είναι το `cert.key`):

```toml
# lldap_config.toml
[ldaps_options]
enabled = true
port = 6360
cert_file = "/data/tls/cert.pem"
key_file = "/data/tls/cert.key"
```

ή `LLDAP_LDAPS_OPTIONS__ENABLED=true`, `LLDAP_LDAPS_OPTIONS__CERT_FILE=...`,
`LLDAP_LDAPS_OPTIONS__KEY_FILE=...` στο περιβάλλον. Κάθε πελάτης LDAP
(Authelia, Nextcloud, Jellyfin, ...) χρειάζεται τότε την CA του MiniCA στον δικό του
χώρο εμπιστοσύνης, σύμφωνα με τις παραπάνω συνταγές για την πλατφόρμα ή τη γλώσσα στην οποία εκτελείται.

## Δημοσίευση του MiniCA μέσω Nginx

Με τη δική του σύνδεση του MiniCA, αρκεί ένα πρόθεμα. Το MiniCA προστατεύει μόνο του τις ιδιωτικές σελίδες του και αυτός ο οδηγός παραμένει δημόσιος στο `/minica/how-to-use`:

```nginx
location /minica/ {
    proxy_pass http://minica:9988;
    include /etc/nginx/snippets/proxy.conf;
}
```

Με SSO (Authelia, oauth2-proxy, ...), το πρόθεμα προστατεύεται, οπότε οι δημόσιες σελίδες χρειάζονται δικό τους κανόνα. Διατηρήστε τις κεφαλίδες ταυτότητας καθαρισμένες σε αυτόν τον κανόνα, επειδή το MiniCA τις εμπιστεύεται όταν προέρχονται από τον proxy:

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

## Έλεγχος ότι λειτουργεί

```sh
openssl s_client -connect intranet.example.com:443 -servername intranet.example.com </dev/null 2>/dev/null | grep "Verify return code"
curl -v https://intranet.example.com/ 2>&1 | grep -E "SSL certificate verify|issuer"
```

Το `Verify return code: 0 (ok)` σημαίνει ότι ο πελάτης βρήκε και εμπιστεύτηκε την CA.
