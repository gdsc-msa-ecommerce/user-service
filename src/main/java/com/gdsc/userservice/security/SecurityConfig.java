package com.gdsc.userservice.security;

import com.gdsc.userservice.filter.CustomLoginFilter;
import com.gdsc.userservice.filter.JwtFilter;
import com.gdsc.userservice.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity(debug = true)
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomAuthenticationProvider customAuthenticationProvider;

    private final PasswordEncoder passwordEncoder;

    private final MemberRepository memberRepository;

    private final AuthenticationSuccessHandler customSuccessHandler;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors().disable()
                .csrf().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .sessionManagement().
                sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http
                .authorizeHttpRequests((customizer) -> customizer
                        .requestMatchers("/").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/login").permitAll()
                        .anyRequest().permitAll()
                )
        ;
        CustomLoginFilter filter = new CustomLoginFilter(authenticationManager());
        filter.setAuthenticationSuccessHandler(customSuccessHandler);
        http
                .addFilterAt(new JwtFilter(), AuthorizationFilter.class)
                .addFilterAt(filter, UsernamePasswordAuthenticationFilter.class)
        ;
        return http.build();
    }

    @Bean
    WebSecurityCustomizer webSecurityCustomizer() {
        return (web -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations()));
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        var customAuthenticationProvider = new CustomAuthenticationProvider(passwordEncoder, memberRepository);
        return new ProviderManager(customAuthenticationProvider);
    }

}
