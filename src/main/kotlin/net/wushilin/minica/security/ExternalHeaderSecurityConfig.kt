package net.wushilin.minica.security

import com.opencsv.CSVReader
import net.wushilin.minica.config.Config
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import java.io.StringReader
import java.util.*


@Configuration
@ConditionalOnProperty(name=["authentication.mode"], matchIfMissing = false, havingValue = "request-header")
class ExternalHeaderSecurityConfig {
    init {
        log.info("initializing default security config")
    }
    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        @JvmStatic
        private val log = LoggerFactory.getLogger(javaClass.enclosingClass)
    }

    @Value("\${request-header.name.username}")
    private lateinit var usernameHeaderName:String

    // group could be group_1, group_2
    // it could also be "group1","group2"
    @Value("\${request-header.name.group:}")
    private lateinit var groupHeaderName:String

    // can use a special group ANY to represent anyone
    @Value("\${request-header.group.admin.name:admin}")
    private lateinit var adminGroupName:String

    // can use a special group ANY to represent anyone
    @Value("\${request-header.group.viewer.name:viewer}")
    private lateinit var viewerGroupName:String



    @Bean
    @Throws(Exception::class)
    fun filterChain(http: HttpSecurity): SecurityFilterChain? {
        val requestHandler = CsrfTokenRequestAttributeHandler()
        requestHandler.setCsrfRequestAttributeName(null);

        val adminRoles = mutableListOf(toUpper(adminGroupName))
        val viewerRoles = mutableListOf(toUpper(viewerGroupName), toUpper(adminGroupName)).toSet().toList()
        log.info("Viewers: $viewerRoles Admins: $adminRoles")
        var builder = http.csrf { csrf ->
            csrf.disable()
        }.authorizeHttpRequests { authz ->
            authz.requestMatchers(AntPathRequestMatcher("/**", "GET")).hasAnyRole(*viewerRoles.toTypedArray())
                .requestMatchers(AntPathRequestMatcher("/**", "POST")).hasAnyRole(*adminRoles.toTypedArray())
                .requestMatchers(AntPathRequestMatcher("/**", "PUT")).hasAnyRole(*adminRoles.toTypedArray())
                .requestMatchers(AntPathRequestMatcher("/**", "DELETE")).hasAnyRole(*adminRoles.toTypedArray())
                .requestMatchers(AntPathRequestMatcher("/**", "PATCH")).denyAll()
                .requestMatchers(AntPathRequestMatcher("/**", "OPTIONS")).denyAll()
                .requestMatchers(AntPathRequestMatcher("/**", "TRACE")).denyAll()
                .requestMatchers(AntPathRequestMatcher("/**", "HEAD")).denyAll()
        }
        builder = builder.addFilterBefore(XHeaderAuthenticationFilter(usernameHeaderName,
            groupHeaderName), UsernamePasswordAuthenticationFilter::class.java)
        return builder.build()
    }

    fun toUpper(what:String):String {
        return what.uppercase(Locale.getDefault())
    }
}