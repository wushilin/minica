package net.wushilin.minica.rest

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.util.concurrent.atomic.AtomicLong

class Greeting(val id: Long, val content: String)


@RestController
class RestService {
    private val template = "Hello, %s!"
    private val counter = AtomicLong()
    @GetMapping("/greeting")
    fun greeting(@RequestParam(value = "name", defaultValue = "World") name: String?): Greeting? {
        return Greeting(counter.incrementAndGet(), java.lang.String.format(template, name))
    }
}