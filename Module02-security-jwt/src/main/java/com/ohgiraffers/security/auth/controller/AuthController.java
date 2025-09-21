package com.ohgiraffers.security.auth.controller;

import com.ohgiraffers.security.auth.dto.LoginRequestDto;
import com.ohgiraffers.security.auth.dto.TokenResponseDTO;
import com.ohgiraffers.security.auth.jwt.JwtTokenProvider;
import com.ohgiraffers.security.auth.service.AuthService;
import com.ohgiraffers.security.domain.user.dto.SignupRequestDto;
import com.ohgiraffers.security.domain.user.dto.UserResponseDto;
import com.ohgiraffers.security.domain.user.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponseDTO> login(@RequestBody @Valid LoginRequestDto request) {
        TokenResponseDTO response = authService.login(request);
        return ResponseEntity.ok(response);
    }



    @PostMapping("/signup")
    public ResponseEntity<UserResponseDto> signup(@RequestBody @Valid SignupRequestDto request) {
        UserResponseDto signResponse = authService.register(request);

        if (signResponse == null) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }

        return ResponseEntity.status(HttpStatus.CREATED).body(signResponse);
    }
}