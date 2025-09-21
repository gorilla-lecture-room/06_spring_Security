package com.ohgiraffers.security.auth.jwt;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.BDDMockito.given;
import static org.mockito.ArgumentMatchers.any;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/*******************************************
 ✅ 테스트: JwtAuthenticationFilter 통합 테스트
 ********************************************/

/*
 테스트 목표:
 - 유효한 JWT를 포함한 요청 → 정상 통과 여부 확인
 - 토큰이 없거나 잘못된 경우 → 인증 실패 응답 확인
*/

@SpringBootTest
@AutoConfigureMockMvc // MockMvc를 자동으로 설정하여 컨트롤러 및 필터 체인에 대한 HTTP 요청을 시뮬레이션할 수 있게 한다.
class JwtAuthenticationFilterTest {

    @Autowired
    private MockMvc mockMvc; // HTTP 요청을 보내고 응답을 검증하는 데 사용됨

    @MockitoBean
    private JwtTokenProvider jwtTokenProvider;

    @Test
    void 토큰이_유효하면_인증_성공_및_필터_통과() throws Exception {
        // given
        String token = "valid.jwt.token";
        Authentication auth = new UsernamePasswordAuthenticationToken("user", token, List.of());
        // Mockito의 given()을 사용하여 jwtTokenProvider의 메소드 동작을 미리 정의 (stubbing)
        // 1. jwtTokenProvider.resolveToken(any()) 호출 시: "valid.jwt.token"을 반환하도록 설정
        //    (any()는 어떤 HttpServletRequest 객체가 오든 동일하게 동작하도록 함)
        given(jwtTokenProvider.resolveToken(any())).willReturn(token);
        // 2. jwtTokenProvider.validateToken("valid.jwt.token") 호출 시: true (유효함)를 반환하도록 설정
        given(jwtTokenProvider.validateToken(token)).willReturn(true);
        // 3. jwtTokenProvider.getAuthentication("valid.jwt.token") 호출 시: 위에서 만든 auth 객체를 반환하도록 설정
        given(jwtTokenProvider.getAuthentication(token)).willReturn(auth);

        // when, then
        mockMvc.perform(get("/api/user/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
    }

    @Test
    void 토큰이_없으면_인증정보_없이_진행() throws Exception {
        mockMvc.perform(get("/api/user/me"))
                .andExpect(status().isUnauthorized()); // Security 설정에 따라 다름
    }
}
