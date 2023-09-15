package net.wushilin.minica.security

import org.springframework.security.crypto.password.PasswordEncoder

class DumbPasswordEncoder: PasswordEncoder {
    override fun encode(rawPassword: CharSequence?): String {
        if(rawPassword == null) {
            return ""
        }
        return rawPassword.toString()
    }

    override fun matches(rawPassword: CharSequence?, encodedPassword: String?): Boolean {
        if(rawPassword != null && encodedPassword != null) {
            if(rawPassword.isNotEmpty() && encodedPassword.isNotEmpty()) {
                return rawPassword.toString() == encodedPassword
            }
        }
        return false
    }
}