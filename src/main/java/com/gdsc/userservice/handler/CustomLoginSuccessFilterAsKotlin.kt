package com.gdsc.userservice.handler

import com.gdsc.getBearerToken
import com.gdsc.somang
import com.gdsc.userservice.service.JwtTokenService
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

@Component
class CustomLoginSuccessFilterAsKotlin(
    private final val jwtTokenService: JwtTokenService,

): OncePerRequestFilter() {
    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val token = request.getBearerToken()
        if (token != null) {
            val userInfo = jwtTokenService.verifyTokenAndGetUserInfo(token)
            if (userInfo != null) {
                val authentication = UsernamePasswordAuthenticationToken(userInfo, null, null)
                SecurityContextHolder.getContext().authentication = authentication
            }
        }
        filterChain.doFilter(request, response)

    }
}