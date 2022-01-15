package net.wushilin.minica.services

import net.wushilin.minica.config.Config
import net.wushilin.minica.openssl.Run
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Service
import java.io.File
import java.util.*

@Service
class DebugService {
    @Autowired
    lateinit var whatTime: Date

    @Autowired
    lateinit var config: Config

    @Autowired
    lateinit var caSvc: CAService

    //@Scheduled(fixedDelay = 3000)
    fun testSchedule() {
        var calist = caSvc.listCA()
        if(calist.size < 10) {
            val createResult = caSvc.createCA(
                "test-ca", "SG", "MyHome", 12000, "",
                "", "", keyLength = 4096
            )
            println("Create CA: $createResult")
            println(caSvc.listCA())
        } else {
            println("We have enough CA: $calist")
        }
        calist = caSvc.listCA()
        println("Getting CA by ID")
        println(caSvc.getCAById(calist.get(0).id))

        var counter = System.currentTimeMillis()
        calist.forEach {
            ca->
            if(caSvc.listCert(ca).size < 5) {
                val createResult = caSvc.createCert(
                    ca, "common-$counter", "US", "a$counter@gmail.com", "Home$counter",
                    3650, "st$counter", "city$counter", "ou$counter", "sha512", 4096,
                    listOf(), listOf("127.0.0.1", "222.222.111.111")
                )
                println("Create cert result: $createResult")
                counter++
            }
        }

        println(caSvc.listCert(calist.get(0)))
    }
}