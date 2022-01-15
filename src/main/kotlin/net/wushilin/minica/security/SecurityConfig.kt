package net.wushilin.minica.security

import net.wushilin.minica.config.Config
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager


@Configuration
@EnableWebSecurity
class CustomWebSecurityConfigurerAdapter : WebSecurityConfigurerAdapter() {
    @Autowired
    private lateinit var config:Config

    @Throws(Exception::class)
    override fun configure(http: HttpSecurity) {
        http.csrf().disable()
            .authorizeRequests()
            .antMatchers("/public/**").permitAll()
            .antMatchers(HttpMethod.GET,"/**").hasAnyRole("viewer", "admin")
            .antMatchers(HttpMethod.POST, "/**").hasAnyRole("admin")
            .antMatchers(HttpMethod.PUT, "/**").hasAnyRole("admin")
            .antMatchers(HttpMethod.DELETE).hasAnyRole("admin")
            .antMatchers(HttpMethod.PATCH).denyAll()
            .antMatchers(HttpMethod.OPTIONS).denyAll()
            .antMatchers(HttpMethod.TRACE).denyAll()
            .antMatchers(HttpMethod.HEAD).denyAll()
            .and()
            .httpBasic()
    }

    @Bean
    override fun userDetailsService(): UserDetailsService {
        return InMemoryUserDetailsManager(config.getAllUsers())
    }
}
