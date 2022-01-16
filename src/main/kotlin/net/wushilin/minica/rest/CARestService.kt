package net.wushilin.minica.rest

import net.wushilin.minica.openssl.*
import net.wushilin.minica.services.CAService
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.web.bind.annotation.*
import org.springframework.web.server.ResponseStatusException
import javax.servlet.http.HttpServletResponse
import java.io.File
import javax.servlet.http.HttpServletRequest

@RestController
class CARestService {
    val log = LoggerFactory.getLogger(CARestService::class.java)

    @Autowired
    private lateinit var caSvc: CAService

    @GetMapping("/ca", produces = arrayOf(MediaType.APPLICATION_JSON_VALUE))
    fun getCAList(): List<CA> {
        return caSvc.listCA()
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

    @GetMapping("/ca/{id}")
    fun getCA(@PathVariable("id") id: String): CA {
        try {
            return caSvc.getCAById(id)
        } catch (ex: Exception) {
            throw ResponseStatusException(
                HttpStatus.NOT_FOUND, "entity not found"
            )
        }
    }

    @PutMapping("/ca/new")
    fun createCA(@RequestBody req: CARequest): CA {
        return caSvc.createCA(req)
    }

    @PutMapping("/ca/import")
    fun importCA(@RequestBody req:ImportCARequest):CA {
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