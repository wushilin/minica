<!-- source-sha256: 51e546526752332fcfc280e7dff9c74d662f180be9dc12f325b1f7754935dbb2 -->
# Faire confiance à une autorité de certification MiniCA

Les certificats émis par MiniCA ne sont acceptés par un client que lorsque ce
client fait confiance à l'AC émettrice. Cette page rassemble les procédures
pour les plateformes et outils courants. Tout part des deux téléchargements
publics dont dispose chaque AC (aucune connexion requise) :

| Téléchargement | URL | À utiliser pour |
| --- | --- | --- |
| Certificat de l'AC (PEM) | `https://ca.example.com/minica/<ca-id>/download` | tout sauf Java |
| Truststore de l'AC (PKCS#12, mot de passe `changeit`) | `https://ca.example.com/minica/download/ca/<ca-id>/truststore` | applications Java / JVM |

Les deux sont également accessibles depuis l'index public des AC à l'adresse `https://ca.example.com/minica/`
et depuis la page de l'AC. Le fichier porte le nom commun (CN) de l'AC, par ex.
`Homelab_CA.pem` ; les exemples ci-dessous l'appellent `minica-ca.pem` / `minica-ca.crt`.

```sh
curl -fsSLo minica-ca.pem https://ca.example.com/minica/<ca-id>/download
openssl x509 -in minica-ca.pem -noout -subject -dates -fingerprint -sha256   # check what you got
```

Seul le **certificat de l'AC** est installé sur les clients — jamais une clé
privée. Si l'AC est une AC intermédiaire, installez plutôt sa racine (ou les deux).

## Systèmes d'exploitation

### Debian / Ubuntu

```sh
sudo cp minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt   # must end in .crt, PEM content
sudo update-ca-certificates
```

Cela ajoute l'AC à `/etc/ssl/certs/ca-certificates.crt`, que curl, wget,
Python, Go, Node (avec `NODE_EXTRA_CA_CERTS` ou `--use-openssl-ca`), apt et
la plupart des autres programmes du système utilisent. `/usr/local/share/ca-certificates/`
est l'endroit approprié pour les ajouts locaux ; `/usr/share/ca-certificates/` appartient
au paquet de la distribution.

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

(Exécutez d'abord `apk add ca-certificates` si `update-ca-certificates` est absent.)

### Arch Linux

```sh
sudo trust anchor --store minica-ca.pem
```

### macOS

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain minica-ca.pem
```

Ou double-cliquez sur le fichier, ajoutez-le au trousseau *Système* dans Accès au trousseau,
ouvrez-le et réglez *Lors de l'utilisation de ce certificat* sur *Toujours faire confiance*. Safari et
Chrome utilisent le trousseau ; Firefox nécessite l'étape supplémentaire ci-dessous.

### Windows

En tant qu'administrateur (PowerShell) :

```powershell
Import-Certificate -FilePath .\minica-ca.pem -CertStoreLocation Cert:\LocalMachine\Root
```

ou `certutil -addstore -f Root minica-ca.pem`, ou double-clic → *Installer le
certificat* → *Ordinateur local* → *Placer tous les certificats dans le magasin
suivant* → *Autorités de certification racines de confiance*. Edge, Chrome et
.NET/PowerShell utilisent ce magasin ; Firefox nécessite l'étape supplémentaire ci-dessous.

### Android

Android n'installe que les fichiers DER ou PEM portant un nom en `.crt`/`.cer` :

```sh
openssl x509 -in minica-ca.pem -outform DER -out minica-ca.crt
```

Copiez-le sur le téléphone, puis *Paramètres → Sécurité → Chiffrement et identifiants →
Installer un certificat → Certificat d'AC*. Android 11+ avertit que le
certificat doit être installé depuis les Paramètres ; c'est le chemin ci-dessus.
Chrome et la plupart des applications lui font alors confiance, mais pas les applications qui épinglent les certificats ou embarquent
leur propre magasin de confiance (ni certaines qui utilisent leur propre pile réseau).

### iOS / iPadOS

Ouvrez le fichier `.pem` sur l'appareil (AirDrop, Mail, Fichiers) → *Réglages → Profil
téléchargé → Installer*, puis activez-le sous *Réglages → Général → Informations →
Réglages de confiance des certificats*.

## Navigateurs

Chrome, Edge et Safari utilisent le magasin du système d'exploitation, les étapes ci-dessus
suffisent donc. **Firefox** conserve son propre magasin, sauf configuration contraire :

- Préférences → Vie privée et sécurité → Certificats → *Afficher les certificats* →
  *Autorités* → *Importer* → cochez *Confirmer cette AC pour identifier des sites web* ; ou
- définissez `security.enterprise_roots.enabled` sur `true` dans `about:config` pour que
  Firefox utilise le magasin système de Windows / macOS ; ou
- sous Linux, importez dans la base NSS du profil :
  `certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.mozilla/firefox/<profile>` (`certutil` provient de `libnss3-tools` / `nss-tools`).

Chromium sous Linux dispose aussi d'un magasin NSS pour les AC installées par l'utilisateur :
`certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.pki/nssdb`.

## Outils en ligne de commande et langages

### curl

```sh
curl --cacert minica-ca.pem https://intranet.example.com/
export CURL_CA_BUNDLE=/path/to/minica-ca.pem     # for a shell session
```

Après l'installation de l'AC dans le magasin système (voir plus haut), aucune option n'est nécessaire.
`CURL_CA_BUNDLE` *remplace* le bundle ; faites-le donc pointer vers un fichier contenant aussi
les AC publiques si vous avez besoin des deux (par ex. ajoutez le PEM de MiniCA à une copie
de `/etc/ssl/certs/ca-certificates.crt`).

### wget

```sh
wget --ca-certificate=minica-ca.pem https://intranet.example.com/
echo "ca_certificate = /path/to/minica-ca.pem" >> ~/.wgetrc
```

### Python

`urllib`, `http.client` et le module `ssl` utilisent les chemins par défaut d'OpenSSL,
c'est-à-dire le magasin système, et respectent `SSL_CERT_FILE` / `SSL_CERT_DIR`. La
bibliothèque `requests` (et tout ce qui est construit dessus, y compris `pip`) utilise
à la place le bundle `certifi` :

```sh
export REQUESTS_CA_BUNDLE=/path/to/minica-ca.pem   # requests; replaces the bundle
export SSL_CERT_FILE=/path/to/minica-ca.pem        # ssl / urllib / httpx
pip config set global.cert /path/to/minica-ca.pem  # pip
```

Pour conserver également les AC publiques, ajoutez le PEM de MiniCA à une copie du bundle
de certifi (`python -m certifi` affiche son chemin) et faites pointer les variables vers
la copie. `pip install pip-system-certs` ou `truststore` fait utiliser à requests
le magasin du système d'exploitation.

### Java / JVM (Kafka, Elasticsearch, Jenkins, ...)

Le téléchargement du truststore de l'AC est un truststore PKCS#12 prêt à l'emploi (mot de passe
`changeit`, l'AC étant stockée comme `trustedCertEntry`) :

```sh
curl -fsSLo minica-truststore.p12 https://ca.example.com/minica/download/ca/<ca-id>/truststore
java -Djavax.net.ssl.trustStore=minica-truststore.p12 \
     -Djavax.net.ssl.trustStorePassword=changeit \
     -Djavax.net.ssl.trustStoreType=PKCS12 -jar app.jar
```

Ce truststore contient *uniquement* l'AC MiniCA. Pour ajouter l'AC au magasin
par défaut du JDK à la place (afin que les AC publiques continuent de fonctionner) :

```sh
keytool -importcert -trustcacerts -noprompt -alias minica \
  -file minica-ca.pem -cacerts -storepass changeit
```

Les clients Kafka utilisent `ssl.truststore.location=minica-truststore.p12`,
`ssl.truststore.password=changeit`, `ssl.truststore.type=PKCS12`.

### Go

Go utilise le magasin système (`crypto/x509` lit `/etc/ssl/certs` sous Linux) et
respecte `SSL_CERT_FILE` / `SSL_CERT_DIR`. Pour ajouter une AC depuis le code :

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

Cela *s'ajoute* aux AC intégrées de Node. `--use-openssl-ca` fait utiliser à Node
le magasin système à la place.

### yt-dlp

yt-dlp est un programme Python et suit les règles de Python : si `certifi` est
installé (le cas habituel), il utilise le bundle de certifi, sinon le magasin
par défaut d'OpenSSL. Soit vous installez l'AC dans le magasin système et supprimez /
contournez certifi, soit vous faites pointer la pile HTTP de yt-dlp vers un bundle contenant les deux :

```sh
cat "$(python3 -m certifi)" minica-ca.pem > ~/.config/yt-dlp/ca-bundle.pem
SSL_CERT_FILE=~/.config/yt-dlp/ca-bundle.pem REQUESTS_CA_BUNDLE=~/.config/yt-dlp/ca-bundle.pem yt-dlp https://media.intranet.example.com/...
```

Évitez `--no-check-certificates` ; cette option désactive entièrement la vérification.

## Serveurs et services

### Nginx

Trois choses différentes se confondent facilement :

- **Présenter un certificat émis par MiniCA.** Téléchargez le
  *Bundle* (zip) du certificat — `cert.pem`, `cert.key` et `ca.pem` — et utilisez
  ```nginx
  ssl_certificate     /etc/nginx/tls/cert.pem;    # or cat cert.pem ca.pem > fullchain.pem
  ssl_certificate_key /etc/nginx/tls/cert.key;
  ```
  Les clients doivent ensuite avoir l'AC installée comme décrit sur cette page.
- **Nginx en tant que client TLS** (proxy vers un serveur amont qui présente un
  certificat MiniCA) :
  ```nginx
  proxy_ssl_verify on;
  proxy_ssl_trusted_certificate /etc/nginx/tls/minica-ca.pem;
  proxy_ssl_name upstream.example.com;
  ```
- **Certificats clients (mTLS) émis par MiniCA :**
  ```nginx
  ssl_client_certificate /etc/nginx/tls/minica-ca.pem;
  ssl_verify_client on;
  ssl_crl /etc/nginx/tls/minica.crl.pem;   # optional: openssl crl -inform DER -in <crl> -out minica.crl.pem
  ```
  La CRL se trouve à l'adresse `https://ca.example.com/minica/crl/<ca-id>` (DER).

### Docker

Pour une **image**, ajoutez l'AC au moment du build afin que chaque outil de l'image la voie :

```dockerfile
# Debian/Ubuntu based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN update-ca-certificates
# Alpine based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN apk add --no-cache ca-certificates && update-ca-certificates
```

Pour un **conteneur que vous ne pouvez pas reconstruire**, montez un bundle contenant déjà
l'AC (par ex. le `/etc/ssl/certs/ca-certificates.crt` de l'hôte après y avoir installé
l'AC) par-dessus le bundle de l'image, ou faites-y pointer les outils à l'intérieur
via les variables d'environnement ci-dessus :

```yaml
    environment:
      SSL_CERT_FILE:        /etc/ssl/certs/ca-certificates.crt   # OpenSSL, Python ssl, Go, Ruby
      REQUESTS_CA_BUNDLE:   /etc/ssl/certs/ca-certificates.crt   # Python requests
      CURL_CA_BUNDLE:       /etc/ssl/certs/ca-certificates.crt   # curl
      NODE_EXTRA_CA_CERTS:  /etc/ssl/certs/ca-certificates.crt   # Node.js
    volumes:
      - /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro
```

Les images basées sur des distributions qui placent le bundle ailleurs
(famille RHEL : `/etc/pki/tls/certs/ca-bundle.crt`) nécessitent plutôt ce chemin.

Le *démon* Docker fait confiance à l'AC d'un registre privé depuis
`/etc/docker/certs.d/<registry:port>/ca.crt`, indépendamment du magasin système.

### LLDAP

LLDAP est un serveur : donnez-lui un certificat émis par MiniCA pour son
écouteur LDAPS (téléchargez le bundle du certificat ; la clé est `cert.key`) :

```toml
# lldap_config.toml
[ldaps_options]
enabled = true
port = 6360
cert_file = "/data/tls/cert.pem"
key_file = "/data/tls/cert.key"
```

ou `LLDAP_LDAPS_OPTIONS__ENABLED=true`, `LLDAP_LDAPS_OPTIONS__CERT_FILE=...`,
`LLDAP_LDAPS_OPTIONS__KEY_FILE=...` dans l'environnement. Chaque client LDAP
(Authelia, Nextcloud, Jellyfin, ...) a ensuite besoin de l'AC MiniCA dans son propre
magasin de confiance, selon les procédures ci-dessus pour la plateforme ou le langage sur lequel il s'exécute.

## Publier MiniCA via Nginx

Avec la connexion propre à MiniCA, un seul préfixe suffit. MiniCA protège lui-même ses pages privées, et ce guide reste public à l'adresse `/minica/how-to-use` :

```nginx
location /minica/ {
    proxy_pass http://minica:9988;
    include /etc/nginx/snippets/proxy.conf;
}
```

Avec le SSO (Authelia, oauth2-proxy, ...), le préfixe est protégé : les pages publiques ont donc besoin de leur propre règle. Videz les en-têtes d'identité dans cette règle, car MiniCA leur fait confiance lorsqu'ils proviennent du proxy :

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

## Vérifier que cela fonctionne

```sh
openssl s_client -connect intranet.example.com:443 -servername intranet.example.com </dev/null 2>/dev/null | grep "Verify return code"
curl -v https://intranet.example.com/ 2>&1 | grep -E "SSL certificate verify|issuer"
```

`Verify return code: 0 (ok)` signifie que le client a trouvé l'AC et lui fait confiance.
