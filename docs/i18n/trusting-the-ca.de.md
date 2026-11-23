<!-- source-sha256: 51e546526752332fcfc280e7dff9c74d662f180be9dc12f325b1f7754935dbb2 -->
# Einer MiniCA-Zertifizierungsstelle vertrauen

Von MiniCA ausgestellte Zertifikate werden von einem Client erst akzeptiert,
wenn dieser Client der ausstellenden CA vertraut. Diese Seite sammelt die
Anleitungen für die gängigen Plattformen und Werkzeuge. Alles beginnt mit den
zwei öffentlichen Downloads, die jede CA bereitstellt (keine Anmeldung nötig):

| Download | URL | Verwendung |
| --- | --- | --- |
| CA-Zertifikat (PEM) | `https://ca.example.com/minica/<ca-id>/download` | alles außer Java |
| CA-Truststore (PKCS#12, Passwort `changeit`) | `https://ca.example.com/minica/download/ca/<ca-id>/truststore` | Java- / JVM-Anwendungen |

Beide sind auch im öffentlichen CA-Index unter `https://ca.example.com/minica/`
und auf der CA-Seite verlinkt. Die Datei trägt den Common Name der CA als Namen,
z. B. `Homelab_CA.pem`; in den folgenden Beispielen heißt sie `minica-ca.pem` / `minica-ca.crt`.

```sh
curl -fsSLo minica-ca.pem https://ca.example.com/minica/<ca-id>/download
openssl x509 -in minica-ca.pem -noout -subject -dates -fingerprint -sha256   # check what you got
```

Auf Clients wird ausschließlich das **CA-Zertifikat** installiert — niemals ein
privater Schlüssel. Ist die CA eine Intermediate-CA, installieren Sie stattdessen
(oder zusätzlich) deren Root-CA.

## Betriebssysteme

### Debian / Ubuntu

```sh
sudo cp minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt   # must end in .crt, PEM content
sudo update-ca-certificates
```

Dadurch wird die CA zu `/etc/ssl/certs/ca-certificates.crt` hinzugefügt, das
curl, wget, Python, Go, Node (mit `NODE_EXTRA_CA_CERTS` oder `--use-openssl-ca`),
apt und die meisten anderen Programme des Systems verwenden.
`/usr/local/share/ca-certificates/` ist der richtige Ort für lokale Ergänzungen;
`/usr/share/ca-certificates/` gehört zum Paket der Distribution.

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

(Führen Sie zuerst `apk add ca-certificates` aus, falls `update-ca-certificates` fehlt.)

### Arch Linux

```sh
sudo trust anchor --store minica-ca.pem
```

### macOS

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain minica-ca.pem
```

Alternativ doppelklicken Sie die Datei, fügen sie in der Schlüsselbundverwaltung
zum Schlüsselbund *System* hinzu, öffnen sie und stellen *Bei Verwendung dieses
Zertifikats* auf *Immer vertrauen*. Safari und Chrome verwenden den
Schlüsselbund; Firefox benötigt den zusätzlichen Schritt weiter unten.

### Windows

Als Administrator (PowerShell):

```powershell
Import-Certificate -FilePath .\minica-ca.pem -CertStoreLocation Cert:\LocalMachine\Root
```

oder `certutil -addstore -f Root minica-ca.pem`, oder per Doppelklick →
*Zertifikat installieren* → *Lokaler Computer* → *Alle Zertifikate in
folgendem Speicher speichern* → *Vertrauenswürdige Stammzertifizierungsstellen*.
Edge, Chrome und .NET/PowerShell verwenden diesen Speicher; Firefox benötigt den
zusätzlichen Schritt weiter unten.

### Android

Android installiert nur DER- oder PEM-Dateien mit der Endung `.crt`/`.cer`:

```sh
openssl x509 -in minica-ca.pem -outform DER -out minica-ca.crt
```

Kopieren Sie die Datei auf das Telefon und wählen Sie dann *Einstellungen →
Sicherheit → Verschlüsselung & Anmeldedaten → Zertifikat installieren →
CA-Zertifikat*. Android 11+ warnt, dass das Zertifikat über die Einstellungen
installiert werden muss; das ist der oben beschriebene Weg. Chrome und die
meisten Apps vertrauen ihm danach, Apps hingegen, die Zertifikate pinnen oder
einen eigenen Truststore mitbringen (und einige, die einen eigenen Netzwerkstack
verwenden), tun das nicht.

### iOS / iPadOS

Öffnen Sie die `.pem`-Datei auf dem Gerät (AirDrop, Mail, Dateien) →
*Einstellungen → Profil geladen → Installieren* und aktivieren Sie sie dann unter
*Einstellungen → Allgemein → Info → Zertifikatsvertrauenseinstellungen*.

## Browser

Chrome, Edge und Safari verwenden den Speicher des Betriebssystems, die obigen
Schritte genügen daher. **Firefox** führt einen eigenen Speicher, sofern nichts
anderes eingestellt ist:

- Einstellungen → Datenschutz & Sicherheit → Zertifikate → *Zertifikate
  anzeigen* → *Zertifizierungsstellen* → *Importieren* → *Dieser CA vertrauen, um
  Websites zu identifizieren* aktivieren; oder
- `security.enterprise_roots.enabled` in `about:config` auf `true` setzen, damit
  Firefox den Systemspeicher von Windows / macOS verwendet; oder
- unter Linux in die NSS-Datenbank des Profils importieren:
  `certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.mozilla/firefox/<profile>` (`certutil` aus `libnss3-tools` / `nss-tools`).

Chromium unter Linux besitzt ebenfalls einen NSS-Speicher für vom Benutzer
installierte CAs:
`certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.pki/nssdb`.

## Kommandozeilenwerkzeuge und Programmiersprachen

### curl

```sh
curl --cacert minica-ca.pem https://intranet.example.com/
export CURL_CA_BUNDLE=/path/to/minica-ca.pem     # for a shell session
```

Nachdem die CA im Systemspeicher installiert wurde (siehe oben), ist keine Option
nötig. `CURL_CA_BUNDLE` *ersetzt* das Bundle; verweisen Sie daher auf eine Datei,
die auch die öffentlichen CAs enthält, wenn Sie beide benötigen (z. B. die
MiniCA-PEM an eine Kopie von `/etc/ssl/certs/ca-certificates.crt` anhängen).

### wget

```sh
wget --ca-certificate=minica-ca.pem https://intranet.example.com/
echo "ca_certificate = /path/to/minica-ca.pem" >> ~/.wgetrc
```

### Python

`urllib`, `http.client` und das Modul `ssl` verwenden die Standardpfade von
OpenSSL, also den Systemspeicher, und beachten `SSL_CERT_FILE` / `SSL_CERT_DIR`.
Die Bibliothek `requests` (und alles, was darauf aufbaut, einschließlich `pip`)
verwendet stattdessen das Bundle von `certifi`:

```sh
export REQUESTS_CA_BUNDLE=/path/to/minica-ca.pem   # requests; replaces the bundle
export SSL_CERT_FILE=/path/to/minica-ca.pem        # ssl / urllib / httpx
pip config set global.cert /path/to/minica-ca.pem  # pip
```

Um auch die öffentlichen CAs zu behalten, hängen Sie die MiniCA-PEM an eine
Kopie des certifi-Bundles an (`python -m certifi` gibt dessen Pfad aus) und
verweisen die Variablen auf die Kopie. `pip install pip-system-certs` oder
`truststore` sorgt dafür, dass requests stattdessen den Speicher des
Betriebssystems verwendet.

### Java / JVM (Kafka, Elasticsearch, Jenkins, ...)

Der Download des CA-Truststores ist ein gebrauchsfertiger PKCS#12-Truststore
(Passwort `changeit`, die CA als `trustedCertEntry` gespeichert):

```sh
curl -fsSLo minica-truststore.p12 https://ca.example.com/minica/download/ca/<ca-id>/truststore
java -Djavax.net.ssl.trustStore=minica-truststore.p12 \
     -Djavax.net.ssl.trustStorePassword=changeit \
     -Djavax.net.ssl.trustStoreType=PKCS12 -jar app.jar
```

Dieser Truststore enthält *nur* die MiniCA-CA. Um die CA stattdessen zum
Standardspeicher des JDK hinzuzufügen (damit öffentliche CAs weiter
funktionieren):

```sh
keytool -importcert -trustcacerts -noprompt -alias minica \
  -file minica-ca.pem -cacerts -storepass changeit
```

Kafka-Clients verwenden `ssl.truststore.location=minica-truststore.p12`,
`ssl.truststore.password=changeit`, `ssl.truststore.type=PKCS12`.

### Go

Go verwendet den Systemspeicher (`crypto/x509` liest unter Linux `/etc/ssl/certs`)
und beachtet `SSL_CERT_FILE` / `SSL_CERT_DIR`. So fügen Sie eine CA im Code hinzu:

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

Dies *ergänzt* die mitgelieferten CAs von Node. `--use-openssl-ca` bewirkt, dass
Node stattdessen den Systemspeicher verwendet.

### yt-dlp

yt-dlp ist ein Python-Programm und folgt den Python-Regeln: Ist `certifi`
installiert (der Normalfall), verwendet es dessen Bundle, andernfalls den
Standardspeicher von OpenSSL. Installieren Sie entweder die CA im Systemspeicher
und entfernen bzw. umgehen Sie certifi, oder verweisen Sie den HTTP-Stack von
yt-dlp auf ein Bundle, das beides enthält:

```sh
cat "$(python3 -m certifi)" minica-ca.pem > ~/.config/yt-dlp/ca-bundle.pem
SSL_CERT_FILE=~/.config/yt-dlp/ca-bundle.pem REQUESTS_CA_BUNDLE=~/.config/yt-dlp/ca-bundle.pem yt-dlp https://media.intranet.example.com/...
```

Vermeiden Sie `--no-check-certificates`; es schaltet die Überprüfung komplett ab.

## Server und Dienste

### Nginx

Drei verschiedene Dinge lassen sich leicht verwechseln:

- **Ein von MiniCA ausgestelltes Zertifikat ausliefern.** Laden Sie das
  *Bundle* (zip) des Zertifikats herunter — `cert.pem`, `cert.key` und `ca.pem` — und verwenden Sie
  ```nginx
  ssl_certificate     /etc/nginx/tls/cert.pem;    # or cat cert.pem ca.pem > fullchain.pem
  ssl_certificate_key /etc/nginx/tls/cert.key;
  ```
  Clients benötigen dann die CA installiert, wie auf dieser Seite beschrieben.
- **Nginx als TLS-Client** (Proxy zu einem Upstream, der ein
  MiniCA-Zertifikat vorlegt):
  ```nginx
  proxy_ssl_verify on;
  proxy_ssl_trusted_certificate /etc/nginx/tls/minica-ca.pem;
  proxy_ssl_name upstream.example.com;
  ```
- **Von MiniCA ausgestellte Client-Zertifikate (mTLS):**
  ```nginx
  ssl_client_certificate /etc/nginx/tls/minica-ca.pem;
  ssl_verify_client on;
  ssl_crl /etc/nginx/tls/minica.crl.pem;   # optional: openssl crl -inform DER -in <crl> -out minica.crl.pem
  ```
  Die CRL befindet sich unter `https://ca.example.com/minica/crl/<ca-id>` (DER).

### Docker

Fügen Sie bei einem **Image** die CA zur Build-Zeit hinzu, damit jedes Werkzeug im Image sie sieht:

```dockerfile
# Debian/Ubuntu based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN update-ca-certificates
# Alpine based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN apk add --no-cache ca-certificates && update-ca-certificates
```

Binden Sie bei einem **Container, den Sie nicht neu bauen können**, ein Bundle ein,
das die CA bereits enthält (z. B. das `/etc/ssl/certs/ca-certificates.crt` des
Hosts, nachdem die CA auf dem Host installiert wurde), und zwar über das Bundle
des Images, oder lassen Sie die Werkzeuge im Container über die oben genannten
Umgebungsvariablen darauf zeigen:

```yaml
    environment:
      SSL_CERT_FILE:        /etc/ssl/certs/ca-certificates.crt   # OpenSSL, Python ssl, Go, Ruby
      REQUESTS_CA_BUNDLE:   /etc/ssl/certs/ca-certificates.crt   # Python requests
      CURL_CA_BUNDLE:       /etc/ssl/certs/ca-certificates.crt   # curl
      NODE_EXTRA_CA_CERTS:  /etc/ssl/certs/ca-certificates.crt   # Node.js
    volumes:
      - /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro
```

Images auf Basis von Distributionen, die das Bundle an anderer Stelle ablegen
(RHEL-Familie: `/etc/pki/tls/certs/ca-bundle.crt`), benötigen stattdessen diesen Pfad.

Der Docker-*Daemon* vertraut der CA einer privaten Registry anhand von
`/etc/docker/certs.d/<registry:port>/ca.crt`, unabhängig vom Systemspeicher.

### LLDAP

LLDAP ist ein Server: Geben Sie ihm für seinen LDAPS-Listener ein von MiniCA
ausgestelltes Zertifikat (laden Sie das Bundle des Zertifikats herunter; der
Schlüssel ist `cert.key`):

```toml
# lldap_config.toml
[ldaps_options]
enabled = true
port = 6360
cert_file = "/data/tls/cert.pem"
key_file = "/data/tls/cert.key"
```

oder `LLDAP_LDAPS_OPTIONS__ENABLED=true`, `LLDAP_LDAPS_OPTIONS__CERT_FILE=...`,
`LLDAP_LDAPS_OPTIONS__KEY_FILE=...` in der Umgebung. Jeder LDAP-Client
(Authelia, Nextcloud, Jellyfin, ...) benötigt dann die MiniCA-CA in seinem
eigenen Truststore, gemäß den obigen Anleitungen für die Plattform oder Sprache,
auf der er läuft.

## MiniCA über Nginx veröffentlichen

Mit der eigenen Anmeldung von MiniCA genügt ein Präfix. MiniCA schützt seine privaten Seiten selbst, und diese Anleitung bleibt unter `/minica/how-to-use` öffentlich:

```nginx
location /minica/ {
    proxy_pass http://minica:9988;
    include /etc/nginx/snippets/proxy.conf;
}
```

Mit SSO (Authelia, oauth2-proxy, ...) ist das Präfix geschützt, daher brauchen die öffentlichen Seiten eine eigene Regel. Leeren Sie in dieser Regel die Identitäts-Header, denn MiniCA vertraut ihnen, wenn sie vom Proxy kommen:

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

## Prüfen, ob es funktioniert

```sh
openssl s_client -connect intranet.example.com:443 -servername intranet.example.com </dev/null 2>/dev/null | grep "Verify return code"
curl -v https://intranet.example.com/ 2>&1 | grep -E "SSL certificate verify|issuer"
```

`Verify return code: 0 (ok)` bedeutet, dass der Client die CA gefunden hat und ihr vertraut.
