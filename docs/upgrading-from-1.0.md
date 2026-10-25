# Upgrading from MiniCA 1.0.x (Kotlin) to 1.2.x (Rust)

MiniCA 1.0.0 – 1.0.4 were the original Kotlin/Spring Boot application. Since
1.0.5 MiniCA is a Rust rewrite with a different storage model, so a plain
image swap does **not** carry your data over:

| | 1.0.x | 1.2.x |
| --- | --- | --- |
| State | Files under `minica.root` (`CAs/<id>/...`) | One SQLite database (`/data/sqlite/db.sqlite` in Docker) |
| Config | `application.properties` | `config.yaml` / `MINICA_*` environment variables |
| Keystores | PEM, PKCS#12, JKS | PEM, PKCS#12 (no JKS; a public PKCS#12 truststore per CA instead) |
| Export | none | YAML backup & restore in the Admin Console |

1.0.x had no export, but it does not need one: the directory tree it wrote
*is* the export. Every CA lives in `<minica.root>/CAs/<ca-id>/` (`ca-cert.pem`,
`ca-key.pem`, `password.txt`, ...) and every certificate in a sub-folder of its
CA (`cert.pem`, `cert.key`, `cert.csr`, `password.txt`, ...). MiniCA 1.2.x can
import that tree directly.

## Option A: import the old data directory (recommended)

`minica --import-legacy <DIR>` walks a 1.0.x `minica.root` (or its `CAs`
folder) and imports every completed CA and certificate through the normal
import path. It keeps:

- the **ids** (the old directory names), so bookmarked URLs such as
  `/minica/cas/<ca-id>` and scripts keep working;
- the **PKCS#12 passwords** from each `password.txt`;
- the original signing requests, so renewals reproduce the same SANs.

Subject, validity, SANs, key type and digest are read from the certificates
themselves. JKS files are not carried over; download the PKCS#12 bundle or
the CA truststore instead. The import is idempotent: items whose id already
exists are skipped, so you can re-run it after fixing a reported problem.

### With Docker

1. Stop the old container, keep its data directory (say `/srv/minica-old`,
   the `minica.root` of the old `application.properties`).
2. Start the new version once so it creates its database, then stop it:
   ```sh
   docker run -d --name minica -p 9988:9988 -v minica-data:/data \
     -e MINICA_ADMIN_PASSWORD='$2b$12$...' \
     -e MINICA_PUBLIC_BASE_URL=http://ca.example.com:9988/minica \
     wushilin/minica:<version>
   docker stop minica
   ```
3. Run the import as a one-off container that mounts both the new volume and
   the old directory. The container runs as uid 10001, so the old files must
   be readable by it (`chmod -R a+rX /srv/minica-old`, or run with
   `--user 0` for this one command):
   ```sh
   docker run --rm -v minica-data:/data -v /srv/minica-old:/legacy:ro \
     --entrypoint /opt/minica/minica wushilin/minica:<version> \
     --import-legacy /legacy -c /opt/minica/config.yaml
   ```
   The report lists what was imported, skipped and failed; the exit status
   is 1 when anything failed.
4. Start the new container again (`docker start minica`) and sign in. The
   admin password now comes from `MINICA_ADMIN_PASSWORD` (preferably a bcrypt
   hash from `minica --gen-password`); the `users.config` accounts of 1.0.x
   are not migrated — recreate the other users in the Admin Console.

### Without Docker

```sh
./minica --import-legacy /opt/minica -c config.yaml   # /opt/minica = old minica.root
```

Stop the server first (or make sure nothing else is writing to the
database). The config file only tells the importer where the database and
the `openssl` binary are.

## Option B: paste certificates through the UI

For a handful of CAs you can also use **Import CA** on the CA list (paste
`ca-cert.pem` and `ca-key.pem`) and then **Import Certificate** on each CA
page (paste `cert.pem` and `cert.key`). This mints new ids and new PKCS#12
passwords (random unless you type one), which is fine when nothing refers to
the old ids.

## After the upgrade

- Check the CA list: subjects, expiry dates and key types are read from the
  certificates. CAs imported by versions up to 1.2.2 were recorded as "issued
  now, valid 3650 days" with made-up `C=XX`/`O=Imported` subject parts; the
  first start of a newer version corrects those rows from the certificates.
- The old `/ca/...` REST endpoints are gone. The new API lives under
  `/minica/api` and is documented at `/minica/swagger`; the
  [Go CLI](../cli/README.md) covers the common automation cases.
- 1.0.x had no revocation. Every imported CA now has a CRL at
  `/minica/crl/<ca-id>`; certificates issued from now on embed that URL.
