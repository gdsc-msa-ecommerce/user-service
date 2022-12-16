package com.gdsc.userservice.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gdsc.userservice.entity.Member;
import com.gdsc.userservice.repository.MemberRepository;
import com.gdsc.userservice.service.JwtTokenService;
import com.gdsc.userservice.service.TokenModel;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.PrintWriter;

@Component
@RequiredArgsConstructor
public class CustomLoginSuccessHandler implements AuthenticationSuccessHandler {
    private final MemberRepository memberRepository;
    private final JwtTokenService jwtTokenService;
    ObjectMapper objectMapper = new ObjectMapper();
    @Value("${jwt.accessTokenDuration}")
    private String ACCESS_TOKEN_DURATION;
    @Value("${jwt.refreshTokenDuration}")
    private String REFRESH_TOKEN_DURATION;
    @Value("${jwt.secretKey}")
    private String JWT_SECRET_KEY;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        var principal = (Member) authentication.getPrincipal();

        String accessToken = jwtTokenService.issueAccessToken(principal.getId());
        String refreshToken = jwtTokenService.issueRefreshToken(principal.getId());

        TokenModel result = TokenModel.builder().accessToken(accessToken).refreshToken(refreshToken).build();

        response.setContentType(String.valueOf(MediaType.APPLICATION_JSON));
        response.setCharacterEncoding("utf-8");
        response.getWriter()
                .write(objectMapper.writeValueAsString(result));
    }
}
