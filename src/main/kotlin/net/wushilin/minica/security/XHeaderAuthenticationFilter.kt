package net.wushilin.minica.security

import com.opencsv.CSVReader
import jakarta.servlet.FilterChain
import jakarta.servlet.ServletException
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import java.io.IOException
import java.io.StringReader
import java.util.*


class XHeaderAuthenticationFilter(private val userHeaderName:String, private val groupHeaderName:String?) : OncePerRequestFilter() {
    init {
        log.info("XHeaderAuthenticationFilter is enabled")
    }

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        @JvmStatic
        private val log = LoggerFactory.getLogger(javaClass.enclosingClass)
    }
    @Throws(ServletException::class, IOException::class)
    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse, filterChain: FilterChain
    ) {
        log.info("Username Header: $userHeaderName, group name header: $groupHeaderName")
        val username:String? = request.getHeader(userHeaderName)
        var groups:String? = null
        if(groupHeaderName != null && groupHeaderName.trim().isNotEmpty()) {
            groups = request.getHeader(groupHeaderName)
        }

        val user = findByToken(username, groups)
        if (user == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token invalid")
        } else {
            log.info("User is $user")
            val authentication = UsernamePasswordAuthenticationToken(user, user.password, user.authorities)
            SecurityContextHolder.getContext().authentication = authentication
            //val session = request.getSession(true)
            //session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext())
            filterChain.doFilter(request, response)
        }
    }

    private fun findByToken(username: String?, groupsString:String?): User? {
        log.info("Creating trusted user by $username and group [$groupsString]")
        if (username == null) {
            return null
        }
        val groups = mutableListOf<String>()
        if(groupsString != null) {
            val groupTokens = parseGroupTokens(groupsString)
            groupTokens?.forEach {
                groups.add(it)
            }
        }
        groups.add("\$any")

        val groupsObj = groups.map {
            SimpleGrantedAuthority("ROLE_${it.uppercase(Locale.getDefault())}")
        }
        return User(
            username,
            "dummy",
            true,
            true,
            true,
            true,
            groupsObj)
    }

    private fun parseGroupTokens(csvToken:String): Array<String>? {
        CSVReader(StringReader(csvToken)).use { reader ->
            return reader.readNext()
        }
    }
}