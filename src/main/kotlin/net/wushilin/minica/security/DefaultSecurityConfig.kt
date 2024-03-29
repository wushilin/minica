package net.wushilin.minica.security

import net.wushilin.minica.config.Config
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.csrf.CookieCsrfTokenRepository
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler
import org.springframework.security.web.util.matcher.AntPathRequestMatcher


@Configuration
@ConditionalOnProperty(name=["authentication.mode"], matchIfMissing = true, havingValue = "default")
class DefaultWebSecurityConfigurerAdapter {
    init {
        log.info("initializing default security config")
    }
    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        @JvmStatic
        private val log = LoggerFactory.getLogger(javaClass.enclosingClass)
    }

    @Autowired
    private lateinit var config: Config

    @Bean
    @Throws(Exception::class)
    fun filterChain(http: HttpSecurity): SecurityFilterChain? {
        var builder = http.csrf{
            csrf ->
            csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            csrf.csrfTokenRequestHandler(CsrfTokenRequestAttributeHandler())
        }.authorizeHttpRequests { authz ->
            authz.requestMatchers(AntPathRequestMatcher("/**", "GET")).hasAnyRole("viewer", "admin")
                    .requestMatchers(AntPathRequestMatcher("/**", "POST")).hasAnyRole("admin")
                    .requestMatchers(AntPathRequestMatcher("/**", "PUT")).hasAnyRole("admin")
                    .requestMatchers(AntPathRequestMatcher("/**", "DELETE")).hasAnyRole("admin")
                    .requestMatchers(AntPathRequestMatcher("/**", "PATCH")).denyAll()
                    .requestMatchers(AntPathRequestMatcher("/**", "OPTIONS")).denyAll()
                    .requestMatchers(AntPathRequestMatcher("/**", "TRACE")).denyAll()
                    .requestMatchers(AntPathRequestMatcher("/**", "HEAD")).denyAll()
        }
        builder = builder.httpBasic {
        }
        return builder.build()
    }

    @Bean
    fun userDetailsService(): UserDetailsService {
        log.info("HTTP Basic User is configured")
        return InMemoryUserDetailsManager(config.getAllUsers())
    }
}
