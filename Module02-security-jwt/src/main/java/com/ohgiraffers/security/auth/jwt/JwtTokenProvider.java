package com.ohgiraffers.security.auth.jwt;

import com.ohgiraffers.security.exception.ExpiredJwtCustomException;
import com.ohgiraffers.security.exception.InvalidJwtCustomException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.stream.Collectors;

/*******************************************
 📖 개념: JwtTokenProvider의 역할과 구조
 ********************************************/

/*
 JwtTokenProvider는 JWT 인증 시스템의 핵심 유틸리티로,
 토큰 발급, 유효성 검증, 사용자 정보 추출 등의 기능을 담당한다.

 ✅ 주요 책임
 - AccessToken / RefreshToken 발급
 - 토큰 파싱 및 클레임 추출 (ex. 사용자 ID, 권한)
 - 토큰 유효성 검증 (만료 여부, 서명 위조)
 - 인증 객체(Authentication) 생성

 ✅ 설계 이유
 - JwtTokenProvider는 인증 필터나 컨트롤러에서 토큰 처리 로직을 분리시켜
   SRP(단일 책임 원칙)를 지키고 테스트/유지보수성을 향상시킨다.

 ✅ 실무 고려사항
 - 서명 키는 application.yml이 아닌 환경 변수나 Secret Manager로 외부화 필요
 - RefreshToken의 경우 DB 또는 Redis와 연동하여 관리하는 것이 일반적
*/

@Component
public class JwtTokenProvider {

    @Value("${jwt.secret}")
    private String secretKey; // 시크릿 키

    @Value("${jwt.access-token-validity-milliseconds}")
    private long ACCESS_TOKEN_EXPIRE_TIME; // 엑세스 토큰 유효시간

    @Value("${jwt.refresh-token-validity-milliseconds}")
    private long REFRESH_TOKEN_EXPIRE_TIME; // 리프래시 토큰 유효시간

    /*
     * key
     * - JWT의 서명(Signature)을 생성하고 검증하는 데 사용되는 핵심 암호화 키 객체로
     *   사용자가 입력한 평문을 암호화 알고리즘에 맞춰 byte[]로 저장하게 된다.
     * - 이 `key`의 기밀성 유지는 JWT 기반 인증 시스템의 보안에서 가장 중요한데
     * - 특히 HMAC과 같은 대칭키 알고리즘에서 이 키가 외부에 노출될 경우, 공격자는
     * - 유효한 토큰을 임의로 생성하거나 기존 토큰을 위변조할 수 있는 심각한 보안 위협이 발생한다.
     * - 따라서 이 키는 환경 변수, 외부 설정 파일, 또는 보안 관리 시스템(예: Vault) 등을 통해
     * - 매우 안전하게 관리되어야 하며, 코드에 직접 하드코딩하는 것은 피해야 한다.
     */
    private SecretKey key;

    @PostConstruct
    public void init() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes); // ✅ 반환 타입: SecretKey
    }

    // 🎯 AccessToken 생성
    public String createAccessToken(Authentication authentication) {
        String username = authentication.getName();

        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(",")); // 예: "ROLE_USER,ROLE_ADMIN"

        return Jwts.builder()
                .subject(username)
                .claim("roles", authorities)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRE_TIME))
                .signWith(key,  Jwts.SIG.HS512) // ✅ signWith만 전달하면 HS256 자동 적용
                .compact();
    }

    // 🎯 RefreshToken 생성
    public String createRefreshToken() {
        return Jwts.builder()
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRE_TIME))
                .signWith(key, Jwts.SIG.HS512)
                .compact();
    }

    // ✅ 토큰 유효성 검사 (JJWT 0.12.x 방식)
    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token);
            return true;

        } catch (ExpiredJwtException e) {
            throw new ExpiredJwtCustomException("Expired JWT token: " + e.getMessage());
        } catch (JwtException | IllegalArgumentException e) {
            throw new InvalidJwtCustomException("Invalid JWT token: " + e.getMessage(), e);
        }
    }

    // 토큰에서 Claims 추출 (만료 예외 발생시키지 않음, 내부 사용)
    private Claims extractClaims(String token, boolean allowExpired) throws InvalidJwtCustomException {
        try {
            return Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            if (allowExpired) {
                return e.getClaims();
            }
            throw new InvalidJwtCustomException("Token expired and claims parsing not allowed for this context.", e);
        } catch (JwtException | IllegalArgumentException e) {
            throw new InvalidJwtCustomException("Invalid JWT, cannot extract claims: " + e.getMessage(), e);
        }
    }


    // 토큰에서 사용자 정보 추출 (Authentication 객체 생성)
    public Authentication getAuthentication(String token) throws InvalidJwtCustomException {
        Claims claims = extractClaims(token, false); // 만료된 토큰은 여기서 걸러짐 (validateToken 이후 호출되므로)
        String username = claims.getSubject();
        String rolesString = claims.get("roles", String.class);

        Collection<? extends GrantedAuthority> authorities = Collections.emptyList();
        if (rolesString != null && !rolesString.trim().isEmpty()) {
            authorities = Arrays.stream(rolesString.split(","))
                    .map(String::trim)
                    .filter(role -> !role.isEmpty())
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        }

        UserDetails userDetails = User.builder()
                .username(username)
                .password("") // 인증된 토큰이므로 비밀번호 불필요
                .authorities(authorities)
                .build();

        return new UsernamePasswordAuthenticationToken(userDetails, token, userDetails.getAuthorities());
    }



    // 만료된 토큰 포함, 토큰에서 사용자 이름(subject) 추출
    public String getUsernameFromToken(String token) throws InvalidJwtCustomException {
        try {
            return extractClaims(token, true).getSubject(); // allowExpired = true
        } catch (JwtException e) { // extractClaims가 InvalidJwtCustomException을 던지지만, 더 넓게 잡을 수 있음
            throw new InvalidJwtCustomException("Failed to get username from token: " + e.getMessage(), e);
        }
    }

    // ✅ 요청 헤더에서 JWT 토큰 추출
    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    // 요청 헤더에서 Refresh Token 추출 (예: "X-Refresh-Token" 헤더 사용)
    public String resolveRefreshToken(HttpServletRequest request) {
        return request.getHeader("X-Refresh-Token");
    }

    public long getRefreshTokenValidityMilliseconds() {
        return REFRESH_TOKEN_EXPIRE_TIME;
    }

}


/*
* - 토큰 재사용 방지를 위해 Redis에 RefreshToken 저장 및 블랙리스트 처리 전략 필요
* - key는 `@PostConstruct`에서 디코딩/변환 → `@Value`만 사용할 경우 Spring Context 순서에 따라 NullPointer 발생 가능
* */