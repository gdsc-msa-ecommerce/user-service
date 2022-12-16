package com.gdsc.userservice.filter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;
import java.util.Map;

public class CustomLoginFilter extends AbstractAuthenticationProcessingFilter {


    private static final AntPathRequestMatcher LOGIN_REQUEST_MATCHER
            = new AntPathRequestMatcher("/api/login", HttpMethod.POST.name());
    private final ObjectMapper objectMapper = new ObjectMapper();

    private final AuthenticationManager authenticationManager;

    public CustomLoginFilter(AuthenticationManager authenticationManager) {
        super(LOGIN_REQUEST_MATCHER);
        this.authenticationManager = authenticationManager;
        setAuthenticationManager(authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        // 로그인 요청시 보내는 json 형식의 바디에서 이메일과 패스워드 추출
        var userInfo = obtainUserInfo(request);
        // 토큰 발급. 아직은 인증되지 않은 토큰을 발급하여 authenticationManager 에게 넘겨준다.
        var authRequest = UsernamePasswordAuthenticationToken
                .unauthenticated(
                        userInfo.get("email"),
                        userInfo.get("password")
                );

        return super.getAuthenticationManager().authenticate(authRequest);
    }

    private Map<String, Object> obtainUserInfo(HttpServletRequest request) throws IOException {
        var inputStream = request.getInputStream();
        var map = objectMapper.readValue(inputStream, new TypeReference<Map<String, Object>>() {
        });

        return map;
    }
}
