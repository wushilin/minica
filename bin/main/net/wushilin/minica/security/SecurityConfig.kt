package net.wushilin.minica.security

import net.wushilin.minica.config.Config
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.util.matcher.AntPathRequestMatcher


@Configuration
class CustomWebSecurityConfigurerAdapter {
    companion object {
        val log = LoggerFactory.getLogger(CustomWebSecurityConfigurerAdapter::class.java)
    }
    @Autowired
    private lateinit var config:Config

    @Bean
    fun filterChain(http:HttpSecurity):SecurityFilterChain {
        http.authorizeHttpRequests { authz ->
                authz.requestMatchers(AntPathRequestMatcher("/**", "GET")).hasAnyRole("viewer", "admin")
                .requestMatchers(AntPathRequestMatcher("/**", "POST")).hasAnyRole("viewer", "admin")
                .requestMatchers(AntPathRequestMatcher("/**", "PUT")).hasAnyRole("viewer", "admin")
                .requestMatchers(AntPathRequestMatcher("/**", "DELETE")).hasAnyRole("viewer", "admin")
                .requestMatchers(AntPathRequestMatcher("/**", "PATCH")).denyAll()
                .requestMatchers(AntPathRequestMatcher("/**", "OPTIONS")).denyAll()
                .requestMatchers(AntPathRequestMatcher("/**", "TRACE")).denyAll()
                .requestMatchers(AntPathRequestMatcher("/**", "HEAD")).denyAll()
                .anyRequest().authenticated()
        }.httpBasic(Customizer.withDefaults())
        log.info("Security is configured")
        val result = http.build()
        return result
    }


    @Bean
    fun userDetailsService(): UserDetailsService {
        log.info("HTTP Basic User is configured")
        return InMemoryUserDetailsManager(config.getAllUsers())
    }
}
