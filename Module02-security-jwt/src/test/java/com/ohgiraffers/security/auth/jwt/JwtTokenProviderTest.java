package com.ohgiraffers.security.auth.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.TestPropertySource;

import javax.crypto.SecretKey;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/*******************************************
 ✅ 테스트: JwtTokenProvider 단위 테스트
 ********************************************/

/*
 테스트 목표:
 1. 토큰 생성 후 파싱 → subject와 동일한지 검증
 2. 토큰 만료 여부 검증
 3. 인증 객체가 정상 생성되는지 검증
*/

@SpringBootTest
// 테스트 실행 시 application.yml 대신 특정 프로퍼티 값을 오버라이드
// 여기서는 토큰 만료 시간 테스트를 위해 짧은 유효 시간을 설정
@TestPropertySource(properties = "jwt.access-token-validity-seconds=1")
class JwtTokenProviderTest {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    // JwtTokenProvider 내부의 key와 동일한 방식으로 테스트용 키 생성 (Claims 직접 검증 시 필요)
    @Value("${jwt.secret}")
    private String base64SecretKeyForTest;
    private SecretKey testVerificationKey;

    @BeforeEach
    void setUp() {
        // JwtTokenProvider의 init()과 동일한 로직으로 테스트 검증용 키 생성
        byte[] keyBytes = io.jsonwebtoken.io.Decoders.BASE64.decode(base64SecretKeyForTest);
        this.testVerificationKey = io.jsonwebtoken.security.Keys.hmacShaKeyFor(keyBytes);
    }

    private Authentication createMockAuthentication(String username, List<String> roles) {
        List<GrantedAuthority> authorities = roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        return new UsernamePasswordAuthenticationToken(username, null, authorities);
    }

    @Test
    @DisplayName("액세스 토큰 생성: 유효한 Authentication 객체로 토큰이 정상적으로 생성된다.")
    void createAccessToken_withValidAuthentication_shouldGenerateToken() {
        // given
        Authentication authentication = createMockAuthentication("testuser", List.of("ROLE_USER", "ROLE_ADMIN"));

        // when
        String accessToken = jwtTokenProvider.createAccessToken(authentication);

        // then
        assertNotNull(accessToken, "액세스 토큰은 null이 아니어야 합니다.");
        assertFalse(accessToken.isEmpty(), "액세스 토큰은 비어있지 않아야 합니다.");

        // 토큰 파싱하여 내용 검증 (testVerificationKey 사용)
        Claims claims = Jwts.parser()
                .verifyWith(testVerificationKey)
                .build()
                .parseSignedClaims(accessToken)
                .getPayload();

        assertEquals("testuser", claims.getSubject(), "토큰의 subject는 사용자 이름이어야 합니다.");
        assertEquals("ROLE_USER,ROLE_ADMIN", claims.get("role", String.class), "\"role\" 클레임이 정확해야 합니다.");
    }

    @Test
    @DisplayName("리프레시 토큰 생성: 정상적으로 생성된다.")
    void createRefreshToken_shouldGenerateToken() {
        // given - 현재 createRefreshToken은 파라미터가 없음

        // when
        String refreshToken = jwtTokenProvider.createRefreshToken();

        // then
        assertNotNull(refreshToken, "리프레시 토큰은 null이 아니어야 합니다.");
        assertFalse(refreshToken.isEmpty(), "리프레시 토큰은 비어있지 않아야 합니다.");

        // 리프레시 토큰은 일반적으로 사용자 특정 클레임이 없을 수 있음 (구현에 따라 다름)
        // 여기서는 유효한 JWT 형태인지, 만료 시간이 설정되었는지 정도만 검증 가능
        assertDoesNotThrow(() -> Jwts.parser()
                .verifyWith(testVerificationKey)
                .build()
                .parseSignedClaims(refreshToken), "리프레시 토큰은 유효한 JWT여야 합니다.");
    }

    @Test
    @DisplayName("토큰 유효성 검증: 유효한 토큰은 true를 반환한다.")
    void validateToken_withValidToken_shouldReturnTrue() {
        // given
        Authentication authentication = createMockAuthentication("validator", List.of("ROLE_VALID"));
        String validToken = jwtTokenProvider.createAccessToken(authentication);

        // when
        boolean isValid = jwtTokenProvider.validateToken(validToken);

        // then
        assertTrue(isValid, "유효한 토큰에 대해 validateToken은 true를 반환해야 합니다.");
    }

    @Test
    @DisplayName("토큰 유효성 검증: 만료된 토큰은 false를 반환한다.")
    void validateToken_withExpiredToken_shouldReturnFalse() throws InterruptedException {
        // given
        // @TestPropertySource 로 인해 accessTokenValidityInSeconds = 1초로 설정됨
        Authentication authentication = createMockAuthentication("expiredUser", List.of("ROLE_USER"));
        String expiredToken = jwtTokenProvider.createAccessToken(authentication);

        // when
        Thread.sleep(1500); // 1.5초 대기하여 토큰 만료 유도

        // then
        boolean isValid = jwtTokenProvider.validateToken(expiredToken);
        assertFalse(isValid, "만료된 토큰에 대해 validateToken은 false를 반환해야 합니다.");
    }

    @Test
    @DisplayName("토큰 유효성 검증: 잘못된 서명 토큰은 false를 반환한다.")
    void validateToken_withInvalidSignature_shouldReturnFalse() {
        // given
        Authentication authentication = createMockAuthentication("user", List.of("ROLE_USER"));
        String token = jwtTokenProvider.createAccessToken(authentication);
        String tamperedToken = token.substring(0, token.length() - 5) + "XXXXX"; // 토큰 일부 조작

        // when
        boolean isValid = jwtTokenProvider.validateToken(tamperedToken);

        // then
        assertFalse(isValid, "잘못된 서명을 가진 토큰에 대해 validateToken은 false를 반환해야 합니다.");
    }

    @Test
    @DisplayName("토큰 유효성 검증: 잘못된 형식 토큰은 false를 반환한다.")
    void validateToken_withMalformedToken_shouldReturnFalse() {
        // given
        String malformedToken = "this.is.not.a.jwt.token";

        // when
        boolean isValid = jwtTokenProvider.validateToken(malformedToken);

        // then
        assertFalse(isValid, "잘못된 형식의 토큰에 대해 validateToken은 false를 반환해야 합니다.");
    }


    @Test
    @DisplayName("사용자 ID 추출: 유효한 토큰에서 사용자 ID(subject)를 정확히 추출한다.")
    void getUserIdFromToken_withValidToken_shouldReturnCorrectUserId() {
        // given
        String expectedUsername = "extractUser";
        Authentication authentication = createMockAuthentication(expectedUsername, List.of("ROLE_TEST"));
        String token = jwtTokenProvider.createAccessToken(authentication);

        // when
        String actualUsername = jwtTokenProvider.getUserIdFromToken(token);

        // then
        assertEquals(expectedUsername, actualUsername, "토큰에서 추출된 사용자 ID가 일치해야 합니다.");
    }

    @Test
    @DisplayName("사용자 ID 추출: 만료된 토큰에서 ID 추출 시 ExpiredJwtException 발생한다.")
    void getUserIdFromToken_withExpiredToken_shouldThrowExpiredJwtException() throws InterruptedException {
        // given
        Authentication authentication = createMockAuthentication("userToExpire", List.of("ROLE_USER"));
        String expiredToken = jwtTokenProvider.createAccessToken(authentication);
        Thread.sleep(1500); // 토큰 만료 대기 (유효시간 1초로 설정됨)

        // when & then
        assertThrows(ExpiredJwtException.class, () -> {
            jwtTokenProvider.getUserIdFromToken(expiredToken);
        }, "만료된 토큰에서 사용자 ID 추출 시 ExpiredJwtException이 발생해야 합니다.");
    }

    @Test
    @DisplayName("인증 객체 생성: 유효한 토큰으로부터 Authentication 객체를 생성한다 (단, 현재 구현은 권한을 비움).")
    void getAuthentication_withValidToken_shouldCreateAuthenticationObject() {
        // given
        String username = "authUser";
        List<String> originalRoles = List.of("ROLE_SUPERVISOR"); // 원본 토큰 생성 시 사용될 역할
        Authentication originalAuthentication = createMockAuthentication(username, originalRoles);
        String token = jwtTokenProvider.createAccessToken(originalAuthentication);

        // when
        Authentication authentication = jwtTokenProvider.getAuthentication(token);

        // then
        assertNotNull(authentication, "생성된 Authentication 객체는 null이 아니어야 합니다.");
        assertEquals(username, authentication.getName(), "Authentication 객체의 사용자 이름이 일치해야 합니다.");
        // ✅ 현재 JwtTokenProvider.getAuthentication() 구현은 authorities를 List.of()로 비워두므로, 이를 검증
        assertTrue(authentication.getAuthorities().isEmpty(),
                "현재 getAuthentication() 구현에 따라 권한 목록은 비어 있어야 합니다.");

        // ℹ️ 만약 getAuthentication()이 "role" 클레임을 파싱하여 권한을 설정하도록 수정된다면,
        //    다음과 같이 검증할 수 있습니다:
        //    List<String> expectedRolesInAuth = originalRoles.stream().sorted().collect(Collectors.toList());
        //    List<String> actualRolesInAuth = authentication.getAuthorities().stream()
        //            .map(GrantedAuthority::getAuthority)
        //            .sorted()
        //            .collect(Collectors.toList());
        //    assertEquals(expectedRolesInAuth, actualRolesInAuth, "Authentication 객체의 권한이 토큰의 'role' 클레임과 일치해야 합니다.");
    }

    @Test
    @DisplayName("요청 헤더에서 토큰 추출: 'Bearer ' 타입으로 토큰이 올바르게 추출된다.")
    void resolveToken_withValidBearerHeader_shouldExtractToken() {
        // given
        MockHttpServletRequest request = new MockHttpServletRequest();
        String tokenValue = "test.token.value";
        request.addHeader("Authorization", "Bearer " + tokenValue);

        // when
        String resolvedToken = jwtTokenProvider.resolveToken(request);

        // then
        assertEquals(tokenValue, resolvedToken, "'Bearer ' 접두사가 제거된 토큰 값이 반환되어야 합니다.");
    }

    @Test
    @DisplayName("요청 헤더에서 토큰 추출: 'Bearer ' 접두사가 없으면 null을 반환한다.")
    void resolveToken_withoutBearerPrefix_shouldReturnNull() {
        // given
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "InvalidTokenFormat");

        // when
        String resolvedToken = jwtTokenProvider.resolveToken(request);

        // then
        assertNull(resolvedToken, "'Bearer ' 접두사가 없는 경우 null이 반환되어야 합니다.");
    }

    @Test
    @DisplayName("요청 헤더에서 토큰 추출: Authorization 헤더가 없으면 null을 반환한다.")
    void resolveToken_withoutAuthorizationHeader_shouldReturnNull() {
        // given
        MockHttpServletRequest request = new MockHttpServletRequest();

        // when
        String resolvedToken = jwtTokenProvider.resolveToken(request);

        // then
        assertNull(resolvedToken, "Authorization 헤더가 없는 경우 null이 반환되어야 합니다.");
    }
}
