package com.gdsc.userservice.controller;

import com.gdsc.userservice.entity.Member;
import com.gdsc.userservice.service.MemberService;
import com.gdsc.userservice.service.TokenModel;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.Errors;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/user")
public class MemberController {

    private final ModelMapper modelMapper;
    private final MemberService memberService;

    // 회원 가입
    @PostMapping("")
    public ResponseEntity<?> register(@RequestBody @Validated RegisterReq registerReq, Errors error) {
        if (error.hasErrors()) {
            throw new IllegalArgumentException("요청 값이 잘못 되었습니다.");
        }

        Member member = modelMapper.map(registerReq, Member.class);
        TokenModel tokenModel = memberService.register(member);

        return ResponseEntity.ok(tokenModel);

    }
}
