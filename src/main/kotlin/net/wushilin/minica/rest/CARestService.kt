package net.wushilin.minica.rest

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import net.wushilin.minica.openssl.*
import net.wushilin.minica.services.CAService
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.web.csrf.CsrfToken
import org.springframework.web.bind.annotation.*
import org.springframework.web.server.ResponseStatusException
import java.io.File
import java.util.*

@RestController
class CARestService {
    val log = LoggerFactory.getLogger(CARestService::class.java)

    @Autowired
    private lateinit var caSvc: CAService

    @GetMapping("/ca/csrf")
    @ResponseBody
    fun getCsrfToken(request: HttpServletRequest): CsrfToken {
        // https://github.com/spring-projects/spring-security/issues/12094#issuecomment-1294150717
        val csrfToken: CsrfToken = request.getAttribute("_csrf") as CsrfToken
        return csrfToken
    }

    @GetMapping("/ca/getAll", produces = arrayOf(MediaType.APPLICATION_JSON_VALUE))
    fun getCAList(request: HttpServletRequest): List<CA> {
        return caSvc.listCA()
    }

    @DeleteMapping("/ca/deleteTest")
    fun deleteTest():String {
        return "DELETE OK"
    }

    @DeleteMapping("/ca/{id}")
    fun deleteCA(@PathVariable("id") id: String): CA {
        try {
            val result = caSvc.getCAById(id)
            caSvc.deleteCA(result)
            return result
        } catch (ex: Exception) {
            throw ResponseStatusException(HttpStatus.NOT_FOUND, "entity not found")
        }
    }

    @DeleteMapping("/ca/{caid}/cert/{certid}")
    fun deleteCert(@PathVariable("caid") caid: String, @PathVariable("certid") certid: String): Cert {
        try {
            val ca = caSvc.getCAById(caid)
            return ca.removeCertById(certid)
        } catch (ex: Exception) {
            throw ResponseStatusException(HttpStatus.NOT_FOUND, "entity not found")
        }
    }

    @GetMapping("/ca/get/{id}")
    fun getCA(@PathVariable("id") id: String): CA {
        try {
            return caSvc.getCAById(id)
        } catch (ex: Exception) {
            throw ResponseStatusException(
                    HttpStatus.NOT_FOUND, "entity not found"
            )
        }
    }

    @PutMapping("/ca/cert/inspect")
    fun inspectCA(@RequestBody req: InspectRequest): InspectRequest {
        if (req.cert.isEmpty()) {
            throw IllegalArgumentException("Invalid cert")
        }
        val parsed = CertParser.parseCert(req.cert)
        log.info("Parsed: $parsed")
        val issuedBy: String = "/C=${parsed["caCountryCode"]!!}/ST=${parsed["caState"]}/L=${parsed["caCity"]}/${parsed["caOrganization"]}/OU=${parsed["caOrganizationUnit"]}/CN=${parsed["caCommonName"]}"
        val subject = "/C=${parsed["certCountryCode"]!!}/ST=${parsed["certState"]}/L=${parsed["certCity"]}/${parsed["certOrganization"]}/OU=${parsed["certOrganizationUnit"]}/CN=${parsed["certCommonName"]}"
        req.info = mapOf(
                "Subject" to subject,
                "Issuer" to issuedBy,
                "Validity" to "From ${Date(parsed["validityStart"]!!.toLong())} to ${Date(parsed["validityEnd"]!!.toLong())}",
                "Valid DNS Names" to parsed["dnsList"]!!,
                "Valid IP Addreses" to parsed["ipList"]!!,
                "Public Key Algorithm" to parsed["pkiAlgorithm"]!!,
                "Signature Algorithm" to parsed["signatureAlgorithm"]!!,
                "Key Usage" to parsed["keyUsage"]!!,
                "Extended Key Usage" to parsed["extendedKeyUsage"]!!,
                "Serial" to parsed["serial"]!!,
                "Version" to parsed["version"]!!,
        )
        //2022-01-17 01:07:16.786  INFO 1946 --- [nio-8080-exec-2] net.wushilin.minica.rest.CARestService   : Parsed: {version=3, serial=178, isCA=false,
        // pkiAlgorithm=4096-bit RSA key, signatureAlgorithm=SHA512withRSA, keyUsage=DigitalSignature,Non_repudiation,Key_Encipherment,
        // extendedKeyUsage=clientAuth,emailProtection,serverAuth, dnsList=ipad, ipList=, validityStart=1641708304000, validityEnd=2272428304000, certCountryCode=SG, certCommonName=ipad, certOrganization=Confluent Singapore Pte. Ltd, certOrganizationUnit=, certCity=Singapore, certState=Singapore, caCountryCode=SG, caCommonName=Wu Shilin Certificate Authority, caOrganization=Confluent Singapore Pte. Ltd., caOrganizationUnit=Professional Services, caCity=Singapore, caState=Singapore}
        return req
    }

    @PutMapping("/ca/new")
    fun createCA(@RequestBody req: CARequest): CA {
        return caSvc.createCA(req)
    }

    @PutMapping("/ca/import")
    fun importCA(@RequestBody req: ImportCARequest): CA {
        return caSvc.importCA(req)
    }

    @PutMapping("/ca/{caid}/new")
    fun createCert(@PathVariable("caid") caid: String, @RequestBody req: CertRequest): Cert {
        val ca = caSvc.getCAById(caid)
        return caSvc.createCert(ca, req)
    }

    @GetMapping("/ca/{id}/cert")
    fun getCACerts(@PathVariable("id") id: String): List<Cert> {
        try {
            val ca = caSvc.getCAById(id)
            return caSvc.listCert(ca)
        } catch (ex: Exception) {
            log.error("Failed to list certs for CA:$id", ex)
            throw ResponseStatusException(
                    HttpStatus.NOT_FOUND, "entity not found"
            )
        }
    }

    @PostMapping("/ca/{caid}/cert/{certid}/renew/{days}")
    fun renewCert(@PathVariable("caid") caid: String, @PathVariable("certid") certid:String, @PathVariable("days") days:Int):Cert {
        try {
            val ca = caSvc.getCAById(caid)
            val cert = ca.getCertById(certid)
            // both exists, good!
            return caSvc.renewCert(ca, cert, days)
        } catch(ex:Exception) {
            log.error("Failed to extend cert by id $caid/$certid for $days days", ex)
            throw ResponseStatusException(
                HttpStatus.INTERNAL_SERVER_ERROR, "entity error"
            )
        }
    }
    @GetMapping("/ca/{caid}/cert/{certid}")
    fun getCACert(@PathVariable("caid") caid: String, @PathVariable("certid") certid: String): Cert {
        try {
            val ca = caSvc.getCAById(caid)
            val cert = ca.getCertById(certid)
            return cert
        } catch (ex: Exception) {
            log.error("Failed to get cert by id $caid/$certid", ex)
            throw ResponseStatusException(
                    HttpStatus.NOT_FOUND, "entity not found"
            )
        }
    }

    @GetMapping("/ca/download/{caid}/truststore")
    fun downloadCATrustStore(
            @PathVariable("caid") caid: String,
            request: HttpServletRequest,
            response: HttpServletResponse
    ) {
        val ca = caSvc.getCAById(caid)
        val file = File(ca.base, "truststore.jks")
        handleDownload("ca-${caid}-truststore.jks", file, request, response)
    }

    @GetMapping("/ca/download/{caid}/password")
    fun downloadCAPassword(
            @PathVariable("caid") caid: String,
            request: HttpServletRequest,
            response: HttpServletResponse
    ) {
        val ca = caSvc.getCAById(caid)
        val file = File(ca.base, "password.txt")
        handleDownload("ca-${caid}-password.txt", file, request, response)
    }

    @GetMapping("/ca/download/{caid}/pkcs12")
    fun downloadCAPKCS12(
            @PathVariable("caid") caid: String,
            request: HttpServletRequest,
            response: HttpServletResponse
    ) {
        val ca = caSvc.getCAById(caid)
        val file = File(ca.base, "ca.p12")
        handleDownload("ca-${caid}.p12", file, request, response)
    }

    @GetMapping("/ca/download/{caid}/cert")
    fun downloadCACert(@PathVariable("caid") caid: String, request: HttpServletRequest, response: HttpServletResponse) {
        val ca = caSvc.getCAById(caid)
        val file = File(ca.base, "ca-cert.pem")
        handleDownload("ca-${caid}-cert.pem", file, request, response)
    }

    @GetMapping("/ca/download/{caid}/key")
    fun downloadCAKey(@PathVariable("caid") caid: String, request: HttpServletRequest, response: HttpServletResponse) {
        val ca = caSvc.getCAById(caid)
        val file = File(ca.base, "ca-key.pem")
        handleDownload("ca-${caid}-key.pem", file, request, response)
    }

    @GetMapping("/ca/download/{caid}/cert/{certid}/bundle")
    fun downloadBundle(
            @PathVariable("caid") caid: String,
            @PathVariable("certid") certid: String,
            request: HttpServletRequest,
            response: HttpServletResponse
    ) {
        val cert = caSvc.getCert(caid, certid)
        val file = File(cert.base, "bundle.zip")
        handleDownload("cert-${certid}.zip", file, request, response)
    }

    @GetMapping("/ca/download/{caid}/cert/{certid}/cert")
    fun downloadCert(
            @PathVariable("caid") caid: String,
            @PathVariable("certid") certid: String,
            request: HttpServletRequest,
            response: HttpServletResponse
    ) {
        val cert = caSvc.getCert(caid, certid)
        val file = File(cert.base, "cert.pem")
        handleDownload("cert-${certid}.pem", file, request, response)
    }

    @GetMapping("/ca/download/{caid}/cert/{certid}/csr")
    fun downloadCertCSR(
            @PathVariable("caid") caid: String,
            @PathVariable("certid") certid: String,
            request: HttpServletRequest,
            response: HttpServletResponse
    ) {
        val cert = caSvc.getCert(caid, certid)
        val file = File(cert.base, "cert.csr")
        handleDownload("cert-${certid}.csr", file, request, response)
    }

    @GetMapping("/ca/download/{caid}/cert/{certid}/key")
    fun downloadKey(
            @PathVariable("caid") caid: String,
            @PathVariable("certid") certid: String,
            request: HttpServletRequest,
            response: HttpServletResponse
    ) {
        val cert = caSvc.getCert(caid, certid)
        val file = File(cert.base, "cert.key")
        handleDownload("cert-${certid}.key", file, request, response)
    }

    @GetMapping("/ca/download/{caid}/cert/{certid}/jks")
    fun downloadJKS(
            @PathVariable("caid") caid: String,
            @PathVariable("certid") certid: String,
            request: HttpServletRequest,
            response: HttpServletResponse
    ) {
        val cert = caSvc.getCert(caid, certid)
        val file = File(cert.base, "cert.jks")
        handleDownload("cert-${certid}.jks", file, request, response)
    }

    @GetMapping("/ca/download/{caid}/cert/{certid}/pkcs12")
    fun downloadPKCS12(
            @PathVariable("caid") caid: String,
            @PathVariable("certid") certid: String,
            request: HttpServletRequest,
            response: HttpServletResponse
    ) {
        val cert = caSvc.getCert(caid, certid)
        val file = File(cert.base, "cert.p12")
        handleDownload("cert-${certid}.p12", file, request, response)
    }

    @GetMapping("/ca/download/{caid}/cert/{certid}/truststore")
    fun downloadTrustStore(
            @PathVariable("caid") caid: String,
            @PathVariable("certid") certid: String,
            request: HttpServletRequest,
            response: HttpServletResponse
    ) {
        val ca = caSvc.getCAById(caid)
        val file = File(ca.base, "truststore.jks")
        handleDownload("cert-${certid}-truststore.jks", file, request, response)
    }

    @GetMapping("/ca/download/{caid}/cert/{certid}/truststorePassword")
    fun downloadTrustStorePassword(
            @PathVariable("caid") caid: String,
            @PathVariable("certid") certid: String,
            request: HttpServletRequest,
            response: HttpServletResponse
    ) {
        val ca = caSvc.getCAById(caid)
        val file = File(ca.base, "password.txt")
        handleDownload("cert-${certid}-truststore-password.txt", file, request, response)
    }

    @GetMapping("/ca/download/{caid}/cert/{certid}/password")
    fun downloadPassword(
            @PathVariable("caid") caid: String, @PathVariable("certid") certid: String,
            request: HttpServletRequest,
            response: HttpServletResponse
    ) {
        val cert = caSvc.getCert(caid, certid)
        val file = File(cert.base, "password.txt")
        handleDownload("cert-${certid}-jks-and-pkcs12-keystore-password.txt", file, request, response)
    }

    fun handleDownload(fileName: String, target: File, request: HttpServletRequest, response: HttpServletResponse) {
        response.setContentType("application/octet-stream")
        response.setHeader("Accept-Ranges", "none")
        response.setHeader("Content-Disposition", "attachment;filename=" + fileName);
        response.setHeader("Content-Length", "${target.length()}")

        target.inputStream().use {
            it.copyTo(response.outputStream)
        }
    }
}