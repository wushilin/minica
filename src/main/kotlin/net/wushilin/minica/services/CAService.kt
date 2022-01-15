package net.wushilin.minica.services

import net.wushilin.minica.IO
import net.wushilin.minica.Template
import net.wushilin.minica.config.Config
import net.wushilin.minica.openssl.*
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.*
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import javax.annotation.PostConstruct


@Service
class CAService {
    val log = LoggerFactory.getLogger(CAService::class.java)

    @Autowired
    lateinit var config: Config

    fun deleteCA(what: CA): Boolean {
        return what.base.deleteRecursively()
    }

    fun getCert(caid: String, certid: String): Cert {
        val ca = this.getCAById(caid)
        return ca.getCertById(certid)
    }

    fun deleteCert(caid: String, certid: String): Cert {
        val ca = this.getCAById(caid)
        return ca.removeCertById(certid)
    }

    @PostConstruct
    fun scan() {
        log.info("Scanning invalid CAs...")
        val base = File(config.minicaRoot, "CAs")
        val files = base.listFiles()
        if(files != null) {
            val directories = files.filter {
                it.isDirectory && !it.name.startsWith(".")
            }

            directories.forEach {
                try {
                    val ca = readCA(it)
                    log.info("Found valid CA: $ca")
                    log.info("Scanning certs in $CA")
                    ca.scan()
                } catch (ex: Exception) {
                    val deleteResult = it.deleteRecursively()
                    log.info("Found invalid CA: $it, delete result: $deleteResult")
                }
            }
        }
    }

    private fun caBaseDir(): File {
        return File(config.minicaRoot, "CAs").absoluteFile
    }

    fun safeCheck(dir: File) {
        if (!dir.absoluteFile.toPath().startsWith(caBaseDir().toPath())) {
            throw java.lang.IllegalArgumentException("Go away")
        }
    }

    fun getCAById(id: String): CA {
        val base = caBaseDir()
        val cadir = File(base, id)

        safeCheck(cadir)
        return readCA(cadir)
    }

    fun deleteCAById(id: String): Boolean {
        try {
            val ca = getCAById(id)
            return deleteCA(ca)
        } catch (ex: Exception) {
            return false
        }
    }

    fun listCA(): List<CA> {
        val base = caBaseDir()
        val files = base.listFiles()
        val directories = files.filter {
            it.isDirectory && !it.name.startsWith(".")
        }
        val result = mutableListOf<CA>()
        directories.forEach {
            try {
                result.add(readCA(it))
            } catch (ex: Exception) {

            }
        }
        return result
    }

    fun readCA(base: File): CA {
        safeCheck(base)
        return CA(base)
    }

    fun createSubject(
        commonName: String,
        countryCode: String,
        organization: String,
        state: String,
        city: String,
        organizationUnit: String
    ): String {
        var subject = ""

        if (countryCode != "") {
            subject = "$subject/C=$countryCode"
        } else {
            throw IllegalArgumentException("CountryCode is required")
        }
        if (state != "") {
            subject = "$subject/ST=$state"
        }
        if (city != "") {
            subject = "$subject/L=$city"
        }
        if (organization != "") {
            subject = "$subject/O=$organization"
        } else {
            throw IllegalArgumentException("organization is required")
        }
        if (organizationUnit != "") {
            subject = "$subject/OU=$organizationUnit"
        }
        if (commonName != "") {
            subject = "$subject/CN=$commonName"
        } else {
            throw IllegalArgumentException("CommonName is required.")
        }
        return subject
    }

    fun createCA(caRequest: CARequest): CA {
        return createCA(
            caRequest.commonName,
            caRequest.countryCode,
            caRequest.organization,
            caRequest.validDays,
            caRequest.state,
            caRequest.city,
            caRequest.organizationUnit,
            caRequest.digestAlgorithm,
            caRequest.keyLength
        )
    }

    fun createCA(
        commonName: String, countryCode: String, organization: String, validDays: Int = 365,
        state: String = "", city: String = "", organizationUnit: String = "",
        digestAlgorithm: String = "sha256", keyLength: Int = 4096
    ): CA {
        // check CA dir is there
        val cadir = caBaseDir()
        if (!cadir.exists()) {
            cadir.mkdirs()
        }
        val uuid = UUID.randomUUID()
        val base = File(cadir, "$uuid")
        base.mkdirs()
        // openssl genrsa 2048 > ca-key.pem
        val processResult1 =
            Run.ExecWait(base, 60000, null, listOf(config.opensslPath, "genrsa", "-out", "ca-key.pem", "$keyLength"))
        // openssl req -new -x509 -nodes -days 365000 \
        //                     -key ca-key.pem \
        //                     -out ca-cert.pem -subj "/C=US/ST=CA/O=Acme, Inc./CN=example.com"
        if (!processResult1.isSuccessful()) {
            // Cleanup is caller's responsibility
            log.error("Failed to create RSA keys for CA ${processResult1}")
            throw IllegalArgumentException("Failed to create RSA Key: ${processResult1.error()}")
        }
        log.info("Successfully generated RSA keys: $processResult1")

        val subject = createSubject(commonName, countryCode, organization, state, city, organizationUnit)
        val processResult2 = Run.ExecWait(
            base, 60000, null, listOf(
                config.opensslPath, "req", "-new", "-x509", "-nodes", "-days", "$validDays",
                "-key", "ca-key.pem", "-out", "ca-cert.pem", "-subj", subject
            )
        )
        if (!processResult2.isSuccessful()) {
            // Cleanup is caller's responsibility
            log.error("Failed to self sign the CA ${processResult1}")
            throw IllegalArgumentException("Failed to create RSA Key: ${processResult2.error()}")
        }

        val random = IO.randomPassword(8)
        val processResult3 = Run.ExecWait(
            base, 60000, null, listOf(
                config.opensslPath, "pkcs12", "-export", "-out", "ca.p12",
                "-in", "ca-cert.pem", "-inkey", "ca-key.pem", "-passout", "pass:$random"
            )
        )
        if (!processResult3.isSuccessful()) {
            log.error("Failed to create CA PKCS12 ${processResult3}")
            throw IllegalArgumentException("Failed to create CA PKCS12: ${processResult3.error()}")
        }
        val processResult4 = Run.ExecWait(
            base, 6000, null, listOf(
                config.keytoolPath, "-import", "-v", "-trustcacerts", "-alias", "${commonName}",
                "-file", "ca-cert.pem", "-keystore", "truststore.jks", "-storepass", "$random", "-noprompt"
            )
        )
        if (!processResult4.isSuccessful()) {
            log.error("Failed to create CA Trust Store ${processResult4}")
            throw IllegalArgumentException("Failed to create CA TrustStore: ${processResult4.error()}")
        }
        File(base, "password.txt").outputStream().use {
            it.write(random.toByteArray())
        }
        log.info("Successfully self signed the CA: $processResult1")
        val meta = Properties()
        meta.put("countryCode", countryCode)
        meta.put("issueTime", "${System.currentTimeMillis()}")
        meta.put("state", state)
        meta.put("city", city)
        meta.put("organization", organization)
        meta.put("organizationUnit", organizationUnit)
        meta.put("commonName", commonName)
        meta.put("validDays", "$validDays")
        meta.put("subject", subject)
        meta.put("keyLength", "$keyLength")
        meta.put("digestAlgorithm", digestAlgorithm)
        FileOutputStream(File(base, "meta.properties")).use {
            meta.store(it, "Generated by MiniCA")
        }
        val template = Template(IO.readClassPath("/openssl-ca.conf"))
        template.apply("%BASE_DIR%", base.absolutePath)
        File(base, "openssl-ca.conf").outputStream().use {
            it.write(template.result.toByteArray())
        }
        FileOutputStream(File(base, "index.txt")).use {
        }
        FileOutputStream(File(base, "serial.txt")).use {
            it.write("00".toByteArray())
        }
        File(base, "certs").mkdirs()
        FileOutputStream(File(base, "CA.complete")).use {
            it.write("Done!".toByteArray())
        }
        return readCA(base);
    }

    private fun createSAN(stringList1: List<String>, prefix: String, additional: String = ""): String {
        val stringList = mutableListOf<String>()
        if (additional != "") {
            stringList.add(additional)
        }
        stringList.addAll(stringList1)
        val result = StringBuilder("")
        stringList.forEachIndexed { index, s ->
            result.append("$prefix.${index + 1} = $s\n")
        }
        return result.toString()
    }

    fun listCert(ca: CA): List<Cert> {
        return ca.listCert()
    }

    fun createCert(ca: CA, certRequest: CertRequest): Cert {
        return createCert(
            ca,
            certRequest.commonName,
            certRequest.countryCode,
            certRequest.email,
            certRequest.organization,
            certRequest.validDays,
            certRequest.state,
            certRequest.city,
            certRequest.organizationUnit,
            certRequest.digestAlgorithm,
            certRequest.keyLength,
            certRequest.dnsList,
            certRequest.ipList
        )
    }

    fun createCert(
        ca: CA,
        commonName: String,
        countryCode: String,
        email: String,
        organization: String,
        validDays: Int = 365,
        state: String = "",
        city: String = "",
        organizationUnit: String = "",
        digestAlgorithm: String = "sha512",
        keyLength: Int = 4096,
        altDNSNames1: List<String> = listOf(),
        altIPs: List<String> = listOf()
    ): Cert {
        val uuid = UUID.randomUUID()
        val certBase = File(ca.base, "$uuid")
        val caBase = ca.base
        certBase.mkdirs()
        val altDNSNames = mutableListOf<String>()
        altDNSNames.add(commonName)
        altDNSNames.addAll(altDNSNames1)
        var subject = createSubject(commonName, countryCode, organization, state, city, organizationUnit)
        // run in the CA Base folder, parent of cert base folder
        val template = Template(IO.readClassPath("/openssl-config.conf"))
        template.apply("%COMMON_NAME%", commonName)
            .apply("%EMAIL%", email)
            .apply("%ORGANIZATION%", organization)
            .apply("%ORGANIZATION_UNIT%", organizationUnit)
            .apply("%CITY%", city)
            .apply("%STATE%", state)
            .apply("%COUNTRY_CODE%", countryCode)
            .apply("%DNS_SAN%", createSAN(altDNSNames, "DNS"))
            .apply("%IP_SAN%", createSAN(altIPs, "IP"))
        val configFile = File(caBase, "openssl-config-${uuid}.conf")
        configFile.outputStream().use {
            it.write(template.result.toByteArray())
        }
        val processResult1 = Run.ExecWait(
            caBase, 60000, null, listOf(
                config.opensslPath, "req", "-config",
                "openssl-config-${uuid}.conf", "-newkey", "rsa:$keyLength", "-$digestAlgorithm", "-nodes",
                "-keyout", "$certBase/cert.key", "-out", "$certBase/cert.csr", "-outform", "PEM", "-subj", "$subject"
            )
        )
        if (!processResult1.isSuccessful()) {
            // Cleanup is caller's responsibility
            log.error("Failed to generate RSA: ${processResult1}")
            throw IllegalArgumentException("Failed to create RSA Key: ${processResult1.error()}")
        }

        val processResult2 = Run.ExecWait(
            caBase, 60000, null, listOf(
                config.opensslPath,
                "ca",
                "-config",
                "openssl-ca.conf",
                "-days",
                "$validDays",
                "-batch",
                "-policy",
                "signing_policy",
                "-extensions",
                "signing_req",
                "-out",
                "$certBase/cert.pem",
                "-infiles",
                "$certBase/cert.csr"
            )
        )
        if (!processResult2.isSuccessful()) {
            // Cleanup is caller's responsibility
            log.error("Failed to sign CSR: ${processResult2}")
            throw IllegalArgumentException("Failed to sign CSR : ${processResult2.error()}")

        }
        val random = IO.randomPassword(8)
        // openssl pkcs12 -export -out Cert.p12 -in cert.pem -inkey key.pem -passin pass:root -passout pass:root
        val processResult3 = Run.ExecWait(
            caBase, 60000, null, listOf(
                config.opensslPath, "pkcs12", "-export", "-out", "$certBase/cert.p12",
                "-in", "$certBase/cert.pem", "-inkey", "$certBase/cert.key", "-passout", "pass:$random"
            )
        )
        if (!processResult3.isSuccessful()) {
            log.error("Failed to convert to PKCS12: ${processResult3}")
            throw IllegalArgumentException("Failed to convert to PKCS12 : ${processResult3.error()}")
        }

        FileOutputStream("$certBase/password.txt").use {
            it.write(random.toByteArray())
        }

        //keytool -importkeystore -srcstorepass changeme -srckeystore $outdir/$CN.p12 -srcstoretype pkcs12  -destkeystore $outdir/$CN.jks -deststoretype jks -deststorepass changeme
        val processResult4 = Run.ExecWait(
            certBase, 60000, null, listOf(
                config.keytoolPath,
                "-importkeystore",
                "-srcstorepass",
                "$random",
                "-srckeystore",
                "cert.p12",
                "-srcstoretype",
                "pkcs12",
                "-destkeystore",
                "cert.jks",
                "-deststoretype",
                "jks",
                "-deststorepass",
                "$random"
            )
        )
        if (!processResult4.isSuccessful()) {
            log.error("Failed to convert to JKS: ${processResult3}")
            throw IllegalArgumentException("Failed to convert to JKS : ${processResult4.error()}")
        }

        //keytool -import -v -trustcacerts -alias server-alias
        //-file server.cer -keystore cacerts.jks -keypass changeit -storepass changeit
        val meta = Properties()
        meta.put("countryCode", countryCode)
        meta.put("issueTime", "${System.currentTimeMillis()}")
        meta.put("state", state)
        meta.put("city", city)
        meta.put("organization", organization)
        meta.put("organizationUnit", organizationUnit)
        meta.put("commonName", commonName)
        meta.put("email", email)
        meta.put("validDays", "$validDays")
        meta.put("subject", subject)
        meta.put("dnsList", altDNSNames.joinToString(";"))
        meta.put("ipList", altIPs.joinToString(";"))
        meta.put("keyLength", "$keyLength")
        meta.put("digestAlgorithm", digestAlgorithm)
        FileOutputStream(File(certBase, "meta.properties")).use {
            meta.store(it, "Generated by MiniCA")
        }
        File(certBase, "CERT.complete").outputStream().use {
            it.write("Done!".toByteArray())
        }
        log.info("Created cert $subject ($certBase) in $ca")
        createBundle(
            certBase,
            File(certBase, "bundle.zip"),
            listOf(
                "cert.csr",
                "cert.jks",
                "cert.key",
                "cert.p12",
                "cert.pem",
                "meta.properties",
                "password.txt=>cert-jks-password.txt",
                "password.txt=>cert-p12-password.txt",
                "../ca-cert.pem=>ca.pem",
                "../truststore.jks",
                "../password.txt=>truststore-jks-password.txt"
            )
        )
        return ca.getCertById(certBase.name)
        // openssl req -config openssl-config.conf -newkey rsa:4096 -sha512 -nodes
        // -keyout $outdir/$CN.key -out $outdir/$CN.csr -outform PEM -subj "/C=SG/ST=Singapore/L=Singapore/O=Confluent Singapore Pte. Ltd/CN=$CN

        // openssl ca -config /opt/CA/CA/openssl-ca.conf -days $DAYS -batch -policy signing_policy -extensions signing_req -out $outdir/$CN.pem -infiles $outdir/$CN.csr
        // openssl pkcs12 -export -inkey $outdir/$CN.key -in $outdir/$CN.pem -out $outdir/$CN.p12 -password pass:changeme
        // keytool -importkeystore -srcstorepass changeme -srckeystore $outdir/$CN.p12 -srcstoretype pkcs12  -destkeystore
        //  $outdir/$CN.jks -deststoretype jks -deststorepass changeme
    }

    fun createBundle(base: File, target: File, namelist: List<String>) {
        FileOutputStream(target).use {
            ZipOutputStream(it).use {
                for (filename in namelist) {
                    val idx = filename.indexOf("=>")
                    var zipFileName = filename.takeLastWhile{it !='/'}
                    var fsFileName = filename
                    if(idx >= 0) {
                       zipFileName = filename.substring(idx + 2)
                       fsFileName = filename.substring(0, idx)
                    }
                    val fileToZip = File(base, fsFileName)
                    FileInputStream(fileToZip).use { theFile ->
                        val zipEntry = ZipEntry(zipFileName)
                        it.putNextEntry(zipEntry)
                        theFile.copyTo(it)
                    }
                }
            }
        }
    }
}