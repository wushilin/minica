package net.wushilin.minica.security

import net.wushilin.minica.config.Config
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.csrf.CookieCsrfTokenRepository
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository
import org.springframework.security.web.util.matcher.AntPathRequestMatcher


@Configuration
class CustomWebSecurityConfigurerAdapter  {
    @Autowired
    private lateinit var config:Config

    private val enableCSRF = false
    @Bean
    @Throws(Exception::class)
    fun filterChain(http: HttpSecurity): SecurityFilterChain? {
        val requestHandler = CsrfTokenRequestAttributeHandler()
        requestHandler.setCsrfRequestAttributeName(null);

        http.csrf { obj ->
                obj.disable()
        }.authorizeHttpRequests {
            authz ->
            authz.requestMatchers(AntPathRequestMatcher("/**", "GET")).hasAnyRole("viewer", "admin")
                 .requestMatchers(AntPathRequestMatcher("/**", "POST")).hasAnyRole("admin")
                 .requestMatchers(AntPathRequestMatcher("/**", "PUT")).hasAnyRole("admin")
                 .requestMatchers(AntPathRequestMatcher("/**", "DELETE")).hasAnyRole("admin")
                 .requestMatchers(AntPathRequestMatcher("/**", "PATCH")).denyAll()
                 .requestMatchers(AntPathRequestMatcher("/**", "OPTIONS")).denyAll()
                 .requestMatchers(AntPathRequestMatcher("/**", "TRACE")).denyAll()
                 .requestMatchers(AntPathRequestMatcher("/**", "HEAD")).denyAll()
        }.httpBasic {
        }
        return http.build()
    }


    @Bean
    fun userDetailsService(): UserDetailsService {
        return InMemoryUserDetailsManager(config.getAllUsers())
    }
}