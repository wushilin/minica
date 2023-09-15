package net.wushilin.minica.config

import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Component
import java.util.*
import java.util.regex.Pattern

@Component
class Config {
    val log = LoggerFactory.getLogger(Config::class.java)
    @Value("\${openssl.path}")
    lateinit var opensslPath:String

    @Value("\${minica.root}")
    lateinit var minicaRoot:String

    @Value("\${keytool.path}")
    lateinit var keytoolPath:String

    @Value("\${users.config}")
    lateinit var userConfigString:String

    @Bean
    fun getConfig():Config {
        return Config()
    }

    @Bean
    fun getDate(): Date {
        return Date()
    }


    fun getAllUsers():List<UserDetails> {
        // user@password:admin,viewer;
        val split1 = userConfigString.split(";")
        val result = mutableListOf<UserDetails>()
        val pattern = Pattern.compile("^([^@]+)@(.+):(admin|viewer)$")
        split1.map{ it.trim() }.filter{ it.isNotEmpty() }.forEach {
            val matcher = pattern.matcher(it)
            if(!matcher.matches()) {
                log.info("$it is not a valid user definition.")
            } else {
                val username = matcher.group(1)
                val password = matcher.group(2)
                val role = matcher.group(3)
                log.info("Adding user $username, password=[reducted(${password.length})], role $role ")
                
                val user: UserDetails = User.withDefaultPasswordEncoder()
                    .username(username)
                    .password(password)
                    .roles(role)
                    .build()

                result.add(user)
            }
        }
        return result
    }
}