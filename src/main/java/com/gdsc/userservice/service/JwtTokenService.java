package com.gdsc.userservice.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gdsc.userservice.entity.Member;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Date;

@Service
@RequiredArgsConstructor
public class JwtTokenService {
    @Value("${jwt.secretKey}")
    private String JWT_SECRET_KEY;
    @Value("${jwt.accessTokenDuration}")
    private String ACCESS_TOKEN_DURATION;
    @Value("${jwt.refreshTokenDuration}")
    private String REFRESH_TOKEN_DURATION;

    private final ObjectMapper objectMapper;

    public String issueAccessToken(Long id) {
        long currentTime = System.currentTimeMillis();
        // access token 생성
        return Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setIssuedAt(new Date(currentTime))
                .setExpiration(new Date(currentTime + Long.parseLong(ACCESS_TOKEN_DURATION)))
                .claim("id", id)
                .signWith(SignatureAlgorithm.HS256, JWT_SECRET_KEY.getBytes())
                .compact();
    }

    public String issueRefreshToken(Long id) {
        long currentTime = System.currentTimeMillis();
        // refresh token 생성
        return Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setIssuedAt(new Date(currentTime))
                .setExpiration(new Date(currentTime + Long.parseLong(REFRESH_TOKEN_DURATION)))
                .claim("id", id)
                .signWith(SignatureAlgorithm.HS256, JWT_SECRET_KEY.getBytes())
                .compact();
    }

    // 토큰 유효성 검증
    public Member verifyTokenAndGetUserInfo(String token) {
        Claims body = Jwts.parser()
                .setSigningKey(JWT_SECRET_KEY.getBytes(StandardCharsets.UTF_8)) // Set Key
                .parseClaimsJws(token) // 파싱 및 검증, 실패 시 예외 던짐.
                .getBody();

        // map to object
        return objectMapper.convertValue(body, Member.class);
    }
}
