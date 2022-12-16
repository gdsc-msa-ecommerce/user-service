package com.gdsc.userservice.service;

import com.gdsc.userservice.entity.Member;
import com.gdsc.userservice.repository.MemberRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class MemberService {
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    private final JwtTokenService tokenService;
    @Transactional
    public TokenModel register(Member member) {
        isDuplicatedEmail(member.getEmail());
        isDuplicatedNickname(member.getNickname());
        String password = member.getPassword();
        String encodedPassword = passwordEncoder.encode(password);
        member.setPassword(encodedPassword);
        Member savedMember = memberRepository.save(member);

        String accessToken = tokenService.issueAccessToken(savedMember.getId());
        String refreshToken = tokenService.issueRefreshToken(savedMember.getId());

        return TokenModel.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    private void isDuplicatedEmail(String email) {
        Optional<Member> member = memberRepository.findByEmail(email);
        if (member.isPresent()) {
            throw new IllegalArgumentException("해당 이메일을 가진 유저가 존재합니다.");
        }
    }

    private void isDuplicatedNickname(String nickname) {
        Optional<Member> member = memberRepository.findByNickname(nickname);
        if (member.isPresent()) {
            throw new IllegalArgumentException("해당 닉네임을 가진 유저가 존재합니다.");
        }
    }
}
