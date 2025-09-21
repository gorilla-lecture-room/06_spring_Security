package com.ohgiraffers.security.auth.handler;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityExceptionHandlerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void 인증되지_않은_사용자는_401을_받는다() throws Exception {
        // perform : 실제 HTTP 요청을 실행하는 메소드
        // get: HTTP GET 요청을 생성
        mockMvc.perform(get("/api/user/me")) // 인증 없음
                .andExpect(status().isUnauthorized()) // andExpect : 메소드로 실행된 요청의 결과를 검증하는 메소드
                .andExpect(content().json("{\"error\":\"인증에 실패하였습니다. 토큰이 유효하지 않거나 없습니다.\"}"));
    }

    @Test
    @WithMockUser(username = "user", roles = "USER")
    void ROLE_USER는_ADMIN_페이지에_접근할_수_없고_403을_받는다() throws Exception {
        mockMvc.perform(get("/api/admin/dashboard"))
                .andExpect(status().isForbidden())
                .andExpect(content().json("{\"error\":\"접근 권한이 없습니다.\"}"));
    }
}