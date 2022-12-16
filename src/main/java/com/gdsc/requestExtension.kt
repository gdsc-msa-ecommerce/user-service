package com.gdsc

import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.HttpHeaders

fun HttpServletRequest.getBearerToken(): String {
    val token = this.getHeader(HttpHeaders.AUTHORIZATION)
    return token.replace("Bearer ", "")
}

fun String.somang(): String {
    return "somang"
}


