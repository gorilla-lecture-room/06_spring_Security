package com.ohgiraffers.security.auth.service;


import com.ohgiraffers.security.auth.dto.LoginRequestDto;
import com.ohgiraffers.security.auth.dto.TokenResponseDTO;
import com.ohgiraffers.security.auth.jwt.JwtTokenProvider;
import com.ohgiraffers.security.auth.token.entity.RefreshToken;
import com.ohgiraffers.security.auth.token.repository.RefreshTokenRepository;
import com.ohgiraffers.security.domain.user.dto.SignupRequestDto;
import com.ohgiraffers.security.domain.user.dto.UserResponseDto;
import com.ohgiraffers.security.domain.user.entity.User;
import com.ohgiraffers.security.domain.user.repository.UserRepository;
import com.ohgiraffers.security.exception.ExpiredJwtCustomException;
import com.ohgiraffers.security.exception.InvalidJwtCustomException;
import com.ohgiraffers.security.exception.InvalidRefreshTokenException;
import jakarta.transaction.Transactional;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;

    public AuthService(AuthenticationManager authenticationManager, JwtTokenProvider jwtTokenProvider, PasswordEncoder passwordEncoder, UserRepository userRepository, RefreshTokenRepository refreshTokenRepository) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    /**
     * 🎯 로그인 처리: AccessToken만 클라이언트로 응답,
     *    RefreshToken은 서버(In-Memory)에 저장
     */
    @Transactional
    public TokenResponseDTO login(LoginRequestDto loginRequestDto) {
        // 1. 사용자 인증 시도
        // AuthenticationManager.authenticate()는 인증 실패 시 AuthenticationException을 발생시킨다
        // authenticate() : 입력된 미인증 객체를 바탕으로 인증 절차를 수행하는 메서드로 인증에 성공하면 Authentication 객체를 반환
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequestDto.getUsername(), loginRequestDto.getPassword())
        );

        String accessToken = jwtTokenProvider.createAccessToken(authentication);
        String newRefreshTokenValue = jwtTokenProvider.createRefreshToken(); // 새 Refresh Token 생성
        System.out.println(authentication.getName());

        // 해당 사용자의 기존 Refresh Token이 있다면 삭제 (선택적: 하나의 세션만 허용하는 경우)
        // refreshTokenRepository.deleteByUsername(authentication.getName());
        refreshTokenRepository.findByUsername(authentication.getName()).ifPresent(refreshTokenRepository::delete);
        refreshTokenRepository.findAll().forEach(System.out::println);

        // 새 Refresh Token을 DB에 저장
        RefreshToken newRefreshToken = new RefreshToken(
                authentication.getName(), // 사용자 이름
                newRefreshTokenValue,     // 생성된 Refresh Token 값
                Instant.now().plusMillis(jwtTokenProvider.getRefreshTokenValidityMilliseconds()) // 만료 시간 설정
        );

        refreshTokenRepository.save(newRefreshToken);

        return new TokenResponseDTO(accessToken, newRefreshTokenValue);
    }


    public UserResponseDto register(SignupRequestDto request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new IllegalArgumentException("이미 사용 중인 사용자명입니다.");
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("이미 사용 중인 이메일입니다.");
        }

        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .email(request.getEmail())
                .role(request.getRoles())
                .build();

        User saveUser = userRepository.save(user);

        return new UserResponseDto(saveUser);
    }



}