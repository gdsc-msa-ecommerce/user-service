package com.gdsc.userservice.controller;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

@Getter
public class RegisterReq {
    @Email
    private String email;
    @NotBlank
    private String password;

    @NotBlank
    private String nickname;
}
