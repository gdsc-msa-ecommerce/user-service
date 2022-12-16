package com.gdsc.userservice.service;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class TokenModel {
    private String accessToken;
    private String refreshToken;
}
