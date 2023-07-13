package net.wushilin.minica

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.scheduling.annotation.EnableScheduling

@SpringBootApplication
@EnableScheduling
class MinicaApplication

fun main(args: Array<String>) {
	runApplication<MinicaApplication>(*args)
}
