package net.wushilin.minica.services

import net.wushilin.minica.config.Config
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Service
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.BasicFileAttributes


@Service
class CronService {
    @Autowired
    private lateinit var config: Config

    private val log = LoggerFactory.getLogger(CronService::class.java)

    @Scheduled(fixedDelay = 300000)
    fun reaper() {
        var countCA = 0L
        var countCert = 0L
        try {
            val baseString = config.minicaRoot
            val caBaseDir = File(baseString, "CAs")
            if (!caBaseDir.isDirectory) {
                log.error("$caBaseDir is not directory.")
                return
            }

            val files = caBaseDir.listFiles()
            var raw = files.filter {
                it.isDirectory
                        && !it.name.startsWith(".")
                        && it.name.matches(Regex("([a-f0-9]{8}(-[a-f0-9]{4}){4}[a-f0-9]{8})", RegexOption.IGNORE_CASE))
            }.filter { it ->
                val attr = Files.readAttributes(it.toPath(), BasicFileAttributes::class.java)
                val fileTime = attr.creationTime()
                val createMillis = fileTime.toMillis()
                val now = System.currentTimeMillis()
                val ageMS = now - createMillis
                ageMS > 600000
            }

            raw.filter {
                !File(it, "CA.complete").exists()
            }.forEach {
                val deleteResult = it.deleteRecursively()
                if(deleteResult) {
                    countCA++
                }
                log.info("Invalid CA Found: $it, deleted => $deleteResult")
            }

            raw.filter {
                File(it, "CA.complete").exists()
            }.forEach { ca ->
                val certFiles = ca.listFiles()
                var certFilesRaw = certFiles.filter { cert ->
                    cert.isDirectory
                            && !cert.name.startsWith(".")
                            && cert.name.matches(
                        Regex(
                            "([a-f0-9]{8}(-[a-f0-9]{4}){4}[a-f0-9]{8})",
                            RegexOption.IGNORE_CASE
                        )
                    )
                }.filter { cert ->
                    val attr = Files.readAttributes(cert.toPath(), BasicFileAttributes::class.java)
                    val fileTime = attr.creationTime()
                    val createMillis = fileTime.toMillis()
                    val now = System.currentTimeMillis()
                    val ageMS = now - createMillis
                    ageMS > 600000
                }

                certFilesRaw.filter { cert ->
                    !File(cert, "CERT.complete").exists()
                }.forEach { cert ->
                    val deleteResult = cert.deleteRecursively()
                    if(deleteResult) {
                        countCert++
                    }
                    log.info("Invalid Cert Found: $ca/$cert, deleted => $deleteResult")
                }
            }
            caBaseDir.listFiles()
        } finally {
            log.info("Reaper finished. $countCA CA deleted, $countCert Certs deleted.")
        }
    }
}