package com.gdsc.userservice.filter;

import com.gdsc.userservice.service.JwtTokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

//@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {
    private final JwtTokenService jwtTokenService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String token = request.getHeader("Authorization");  // "Bearer "...
        if (token != null) {
            var parsedToken = token.replace("Bearer ", "");
            var userInfo = jwtTokenService.verifyTokenAndGetUserInfo(parsedToken);
            // 토큰이 유효하여 유저정보를 성공적으로 반환했다면 SecurityContextHolder 에 인증객체를 저장
            if (userInfo != null) {
                var authentication = new UsernamePasswordAuthenticationToken(userInfo, null, null);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        filterChain.doFilter(request, response);
    }
}
