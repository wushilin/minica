package net.wushilin.minica

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.ComponentScan
import org.springframework.scheduling.annotation.EnableScheduling

@SpringBootApplication
@ComponentScan
@EnableScheduling
class MinicaApplication

fun main(args: Array<String>) {
	runApplication<MinicaApplication>(*args)
}
