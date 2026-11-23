<!-- source-sha256: 51e546526752332fcfc280e7dff9c74d662f180be9dc12f325b1f7754935dbb2 -->
# Como confiar em uma autoridade certificadora MiniCA

Os certificados emitidos pelo MiniCA só são aceitos por um cliente depois que
esse cliente passa a confiar na CA emissora. Esta página reúne as receitas
para as plataformas e ferramentas mais comuns. Tudo parte dos dois downloads
públicos que toda CA possui (sem necessidade de login):

| Download | URL | Para que serve |
| --- | --- | --- |
| Certificado da CA (PEM) | `https://ca.example.com/minica/<ca-id>/download` | tudo, exceto Java |
| Truststore da CA (PKCS#12, senha `changeit`) | `https://ca.example.com/minica/download/ca/<ca-id>/truststore` | aplicações Java / JVM |

Ambos também estão linkados no índice público de CAs em `https://ca.example.com/minica/`
e na página da CA. O arquivo recebe o nome do common name da CA, por exemplo
`Homelab_CA.pem`; os exemplos abaixo o chamam de `minica-ca.pem` / `minica-ca.crt`.

```sh
curl -fsSLo minica-ca.pem https://ca.example.com/minica/<ca-id>/download
openssl x509 -in minica-ca.pem -noout -subject -dates -fingerprint -sha256   # check what you got
```

Somente o **certificado da CA** é instalado nos clientes — nunca uma chave
privada. Se a CA for intermediária, instale a raiz dela (ou ambas).

## Sistemas operacionais

### Debian / Ubuntu

```sh
sudo cp minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt   # must end in .crt, PEM content
sudo update-ca-certificates
```

Isso adiciona a CA a `/etc/ssl/certs/ca-certificates.crt`, usado por curl, wget,
Python, Go, Node (com `NODE_EXTRA_CA_CERTS` ou `--use-openssl-ca`), apt e
a maioria dos demais programas do sistema. `/usr/local/share/ca-certificates/`
é o local correto para acréscimos locais; `/usr/share/ca-certificates/` pertence
ao pacote da distribuição.

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

(Execute antes `apk add ca-certificates` se `update-ca-certificates` não existir.)

### Arch Linux

```sh
sudo trust anchor --store minica-ca.pem
```

### macOS

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain minica-ca.pem
```

Ou dê um duplo clique no arquivo, adicione-o ao chaveiro *System* no Keychain Access,
abra-o e defina *When using this certificate* como *Always Trust*. Safari e
Chrome usam o chaveiro; o Firefox precisa da etapa extra abaixo.

### Windows

Como administrador (PowerShell):

```powershell
Import-Certificate -FilePath .\minica-ca.pem -CertStoreLocation Cert:\LocalMachine\Root
```

ou `certutil -addstore -f Root minica-ca.pem`, ou dê um duplo clique → *Install
Certificate* → *Local Machine* → *Place all certificates in the following
store* → *Trusted Root Certification Authorities*. Edge, Chrome e
.NET/PowerShell usam esse repositório; o Firefox precisa da etapa extra abaixo.

### Android

O Android só instala arquivos DER ou PEM com nome `.crt`/`.cer`:

```sh
openssl x509 -in minica-ca.pem -outform DER -out minica-ca.crt
```

Copie-o para o telefone e depois siga *Settings → Security → Encryption & credentials →
Install a certificate → CA certificate*. O Android 11+ avisa que o
certificado deve ser instalado pelas Configurações; esse é o caminho acima.
O Chrome e a maioria dos aplicativos passam então a confiar nele, mas aplicativos que fazem pinning de certificados ou trazem
seu próprio repositório de confiança (e alguns que usam sua própria pilha de rede) não confiarão.

### iOS / iPadOS

Abra o `.pem` no dispositivo (AirDrop, Mail, Arquivos) → *Settings → Profile
Downloaded → Install* e depois ative-o em *Settings → General → About →
Certificate Trust Settings*.

## Navegadores

Chrome, Edge e Safari usam o repositório do sistema operacional, portanto as etapas acima
bastam. O **Firefox** mantém seu próprio repositório, a menos que seja configurado de outra forma:

- Preferences → Privacy & Security → Certificates → *View Certificates* →
  *Authorities* → *Import* → marque *Trust this CA to identify websites*; ou
- defina `security.enterprise_roots.enabled` como `true` em `about:config` para que o
  Firefox use o repositório do sistema Windows / macOS; ou
- no Linux, importe para o banco de dados NSS do perfil:
  `certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.mozilla/firefox/<profile>` (`certutil` vem de `libnss3-tools` / `nss-tools`).

O Chromium no Linux também possui um repositório NSS para CAs instaladas pelo usuário:
`certutil -A -n "MiniCA" -t "C,," -i minica-ca.pem -d sql:$HOME/.pki/nssdb`.

## Ferramentas de linha de comando e linguagens

### curl

```sh
curl --cacert minica-ca.pem https://intranet.example.com/
export CURL_CA_BUNDLE=/path/to/minica-ca.pem     # for a shell session
```

Depois de instalar a CA no repositório do sistema (acima), nenhuma opção é necessária.
`CURL_CA_BUNDLE` *substitui* o bundle; portanto, aponte-o para um arquivo que também
contenha as CAs públicas se precisar de ambos (por exemplo, acrescente o PEM do MiniCA a uma cópia
de `/etc/ssl/certs/ca-certificates.crt`).

### wget

```sh
wget --ca-certificate=minica-ca.pem https://intranet.example.com/
echo "ca_certificate = /path/to/minica-ca.pem" >> ~/.wgetrc
```

### Python

`urllib`, `http.client` e o módulo `ssl` usam os caminhos padrão do OpenSSL,
ou seja, o repositório do sistema, e respeitam `SSL_CERT_FILE` / `SSL_CERT_DIR`. A
biblioteca `requests` (e tudo o que é construído sobre ela, inclusive o `pip`) usa, em vez disso, o
bundle do `certifi`:

```sh
export REQUESTS_CA_BUNDLE=/path/to/minica-ca.pem   # requests; replaces the bundle
export SSL_CERT_FILE=/path/to/minica-ca.pem        # ssl / urllib / httpx
pip config set global.cert /path/to/minica-ca.pem  # pip
```

Para manter também as CAs públicas, acrescente o PEM do MiniCA a uma cópia do
bundle do certifi (`python -m certifi` imprime seu caminho) e aponte as variáveis para a
cópia. `pip install pip-system-certs` ou `truststore` faz o requests usar o
repositório do sistema operacional.

### Java / JVM (Kafka, Elasticsearch, Jenkins, ...)

O download do truststore da CA é um truststore PKCS#12 pronto para uso (senha
`changeit`, com a CA armazenada como `trustedCertEntry`):

```sh
curl -fsSLo minica-truststore.p12 https://ca.example.com/minica/download/ca/<ca-id>/truststore
java -Djavax.net.ssl.trustStore=minica-truststore.p12 \
     -Djavax.net.ssl.trustStorePassword=changeit \
     -Djavax.net.ssl.trustStoreType=PKCS12 -jar app.jar
```

Esse truststore contém *apenas* a CA do MiniCA. Para adicionar a CA ao
repositório padrão do JDK (de modo que as CAs públicas continuem funcionando):

```sh
keytool -importcert -trustcacerts -noprompt -alias minica \
  -file minica-ca.pem -cacerts -storepass changeit
```

Os clientes Kafka usam `ssl.truststore.location=minica-truststore.p12`,
`ssl.truststore.password=changeit`, `ssl.truststore.type=PKCS12`.

### Go

O Go usa o repositório do sistema (`crypto/x509` lê `/etc/ssl/certs` no Linux) e
respeita `SSL_CERT_FILE` / `SSL_CERT_DIR`. Para adicionar uma CA por código:

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

Isso *acrescenta* às CAs embutidas do Node. `--use-openssl-ca` faz o Node usar o
repositório do sistema.

### yt-dlp

O yt-dlp é um programa Python e segue as regras do Python: com o `certifi`
instalado (o caso usual) ele usa o bundle do certifi; caso contrário, o repositório
padrão do OpenSSL. Instale a CA no repositório do sistema e remova /
contorne o certifi, ou aponte a pilha HTTP do yt-dlp para um bundle que contenha ambos:

```sh
cat "$(python3 -m certifi)" minica-ca.pem > ~/.config/yt-dlp/ca-bundle.pem
SSL_CERT_FILE=~/.config/yt-dlp/ca-bundle.pem REQUESTS_CA_BUNDLE=~/.config/yt-dlp/ca-bundle.pem yt-dlp https://media.intranet.example.com/...
```

Evite `--no-check-certificates`; ele desativa totalmente a verificação.

## Servidores e serviços

### Nginx

Três coisas diferentes são fáceis de confundir:

- **Servir um certificado emitido pelo MiniCA.** Baixe o *Bundle* (zip) do
  certificado — `cert.pem`, `cert.key` e `ca.pem` — e use
  ```nginx
  ssl_certificate     /etc/nginx/tls/cert.pem;    # or cat cert.pem ca.pem > fullchain.pem
  ssl_certificate_key /etc/nginx/tls/cert.key;
  ```
  Os clientes então precisam ter a CA instalada conforme descrito nesta página.
- **Nginx como cliente TLS** (fazendo proxy para um upstream que apresenta um
  certificado MiniCA):
  ```nginx
  proxy_ssl_verify on;
  proxy_ssl_trusted_certificate /etc/nginx/tls/minica-ca.pem;
  proxy_ssl_name upstream.example.com;
  ```
- **Certificados de cliente (mTLS) emitidos pelo MiniCA:**
  ```nginx
  ssl_client_certificate /etc/nginx/tls/minica-ca.pem;
  ssl_verify_client on;
  ssl_crl /etc/nginx/tls/minica.crl.pem;   # optional: openssl crl -inform DER -in <crl> -out minica.crl.pem
  ```
  A CRL está em `https://ca.example.com/minica/crl/<ca-id>` (DER).

### Docker

Para uma **imagem**, adicione a CA durante o build para que todas as ferramentas da imagem a enxerguem:

```dockerfile
# Debian/Ubuntu based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN update-ca-certificates
# Alpine based
COPY minica-ca.pem /usr/local/share/ca-certificates/minica-ca.crt
RUN apk add --no-cache ca-certificates && update-ca-certificates
```

Para um **contêiner que você não pode reconstruir**, monte um bundle que já contenha
a CA (por exemplo, o `/etc/ssl/certs/ca-certificates.crt` do host depois de instalar
a CA no host) sobre o bundle da imagem, ou aponte as ferramentas internas para ele
por meio das variáveis de ambiente acima:

```yaml
    environment:
      SSL_CERT_FILE:        /etc/ssl/certs/ca-certificates.crt   # OpenSSL, Python ssl, Go, Ruby
      REQUESTS_CA_BUNDLE:   /etc/ssl/certs/ca-certificates.crt   # Python requests
      CURL_CA_BUNDLE:       /etc/ssl/certs/ca-certificates.crt   # curl
      NODE_EXTRA_CA_CERTS:  /etc/ssl/certs/ca-certificates.crt   # Node.js
    volumes:
      - /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro
```

Imagens baseadas em distribuições que mantêm o bundle em outro lugar
(família RHEL: `/etc/pki/tls/certs/ca-bundle.crt`) precisam desse caminho.

O *daemon* do Docker confia na CA de um registry privado a partir de
`/etc/docker/certs.d/<registry:port>/ca.crt`, independentemente do repositório do sistema.

### LLDAP

O LLDAP é um servidor: forneça a ele um certificado emitido pelo MiniCA para o
listener LDAPS (baixe o bundle do certificado; a chave é `cert.key`):

```toml
# lldap_config.toml
[ldaps_options]
enabled = true
port = 6360
cert_file = "/data/tls/cert.pem"
key_file = "/data/tls/cert.key"
```

ou `LLDAP_LDAPS_OPTIONS__ENABLED=true`, `LLDAP_LDAPS_OPTIONS__CERT_FILE=...`,
`LLDAP_LDAPS_OPTIONS__KEY_FILE=...` no ambiente. Todo cliente LDAP
(Authelia, Nextcloud, Jellyfin, ...) precisa então da CA do MiniCA em seu próprio
repositório de confiança, conforme as receitas acima para a plataforma ou linguagem em que ele roda.

## Publicar o MiniCA através do Nginx

Com o login próprio do MiniCA, um prefixo é suficiente. O MiniCA protege as suas páginas privadas e este guia continua público em `/minica/how-to-use`:

```nginx
location /minica/ {
    proxy_pass http://minica:9988;
    include /etc/nginx/snippets/proxy.conf;
}
```

Com SSO (Authelia, oauth2-proxy, ...), o prefixo fica protegido, por isso as páginas públicas precisam de uma regra própria. Mantenha os cabeçalhos de identidade vazios nessa regra, porque o MiniCA confia neles quando vêm do proxy:

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

## Verificando se funciona

```sh
openssl s_client -connect intranet.example.com:443 -servername intranet.example.com </dev/null 2>/dev/null | grep "Verify return code"
curl -v https://intranet.example.com/ 2>&1 | grep -E "SSL certificate verify|issuer"
```

`Verify return code: 0 (ok)` significa que o cliente encontrou a CA e confiou nela.
