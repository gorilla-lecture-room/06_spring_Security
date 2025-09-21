package com.ohgiraffers.security.config;

import com.ohgiraffers.security.auth.handler.CustomAccessDeniedHandler;
import com.ohgiraffers.security.auth.handler.CustomAuthenticationEntryPoint;
import com.ohgiraffers.security.auth.jwt.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

/*******************************************
 📖 개념: SecurityFilterChain 설정의 목적과 구성
 ********************************************/

/*
 Spring Security 기본 설정은 formLogin + 세션 인증 방식이다.
 JWT 기반 인증을 사용하기 위해 다음을 비활성화 및 커스터마이징해야 한다:

 - formLogin, logout, sessionManagement, csrf 등을 disable
 - Stateless 정책 적용
 - JwtAuthenticationFilter 등록
 - 인증 실패/권한 거부 핸들러 등록

 ✅ 핵심 개념 요약:
 - SecurityFilterChain: 요청 → 필터 → 인증/인가 → 컨트롤러 로직 처리
 - Stateless 환경에선 세션이 없기 때문에 토큰 기반 인증 필터가 필수
 - 인증 예외 응답 커스터마이징 필요
*/
/*******************************************
 🛠 실습: SecurityConfig.java 설정
 ********************************************/

@Configuration
@EnableWebSecurity                     // URL 경로 기반 필터 보안
@EnableMethodSecurity(                 // 메서드 보안 활성화
        prePostEnabled = true,            // @PreAuthorize / @PostAuthorize SpEL을 사용하면 역할(Role) 기반 검사뿐만 아니라, 현재 인증된 사용자 정보까지 정의 가능
        securedEnabled = true,            // @Secured({"ROLE_ADMIN", "ROLE_EDITOR"})  지정된 역할(들) 중 하나라도 현재 사용자가 가지고 있으면 메소드 실행을 허용
        jsr250Enabled = true              // @RolesAllowed @Secured와 같이 둘 중 하나라도 가지고 있으면 허용 하지만 역할 이름에 ROLE_ 접두사를 요구하지 않음
)
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final CustomAccessDeniedHandler accessDeniedHandler;
    private final CustomAuthenticationEntryPoint authenticationEntryPoint;

    @Autowired
    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter,
                          CustomAccessDeniedHandler accessDeniedHandler,
                          CustomAuthenticationEntryPoint authenticationEntryPoint) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.accessDeniedHandler = accessDeniedHandler;
        this.authenticationEntryPoint = authenticationEntryPoint;
    }


    /**
     * CORS 설정을 위한 {@link CorsConfigurationSource} 빈을 정의
     * 애플리케이션의 모든 경로("/**")에 대해 CORS 규칙을 적용.
     * @return {@link CorsConfigurationSource} 객체
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // ✅ 허용할 출처(Origin) 패턴 설정
        // 예: 프론트엔드 개발 서버(localhost:3000), 실제 배포된 프론트엔드 도메인
        // "*" 대신 구체적인 도메인이나 패턴을 사용하는 것이 보안상 좋다.
        configuration.setAllowedOriginPatterns(Arrays.asList(
                "http://localhost:3000", // React, Vue 등의 개발서버
                "http://localhost:8081", // 다른 로컬 개발 환경
                "https://your-production-frontend.com" // 실제 서비스 프론트엔드 도메인
                // "*" // 모든 출처 허용 (개발 초기에는 편리하나, 프로덕션에서는 특정 출처만 허용 권장)
        ));

        // ✅ 허용할 HTTP 메소드 설정
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));

        // ✅ 요청에서 허용할 HTTP 헤더 설정
        // "Authorization" (JWT 토큰 전송), "Content-Type" 등 필요한 헤더를 명시
        configuration.setAllowedHeaders(Arrays.asList(
                "Authorization",
                "Content-Type",
                "X-Requested-With",
                "Accept",
                "Origin",
                "Access-Control-Request-Method",
                "Access-Control-Request-Headers",
                "X-Refresh-Token" // 리프레시 토큰을 위한 커스텀 헤더 (예시)
        ));

        // ✅ 클라이언트(브라우저)에게 노출할 수 있는 응답 헤더 설정
        // JWT 토큰을 응답 헤더로 전달하는 경우(예: 토큰 재발급 시) 해당 헤더를 명시해야
        // 클라이언트 JavaScript에서 접근 가능
        configuration.setExposedHeaders(Arrays.asList(
                "Authorization",
                "New-Access-Token" // 새 액세스 토큰 전달용 커스텀 헤더 (예시)
        ));

        // ✅ 자격 증명(쿠키, Authorization 헤더 등)을 허용할지 여부 설정
        // true로 설정해야 쿠키를 사용한 인증이나 Authorization 헤더를 통한 토큰 인증이 가능.
        configuration.setAllowCredentials(true);

        // ✅ OPTIONS 사전 요청(Preflight Request)의 결과를 캐시할 시간(초 단위) 설정
        configuration.setMaxAge(3600L); // 1시간

        // UrlBasedCorsConfigurationSource 객체를 생성하고, 모든 경로("/**")에 대해 위에서 정의한 CORS 설정을 등록합니다.
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }


    /*
     * AuthenticationManager 설정! 🔐
     * Spring Security에서 AuthenticationManager는 인증(로그인) 과정을 총괄하는 중요한 클래스이다.
     * 사용자가 보낸 아이디와 비밀번호 같은 인증 정보를 받아서,
     * 진짜 사용자인지 아닌지 확인하는 복잡한 과정을 이 처리하게 된다.
     *
     * AuthenticationConfiguration 객체를 받아서 getAuthenticationManager() 메서드로
     * AuthenticationManager를 가져오는 방식다.
     * 스프링 부트가 Security 설정을 자동으로 해줄 때 사용하는 설정 정보라고 보면 돼!
     *
     * 요렇게 설정해두면 Spring Security 필터들이 인증이 필요할 때 이 친구를 찾아와서
     * "이 사용자가 맞는지 확인 좀 해주세요!" 하고 부탁하게 된단다. 😉
-     *
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        /*
        * csrf (Cross-Site Request Forgery)
        *  인증된 사용자(로그인된 사용자)의 권한을 도용하여 사용자가 의도하지 않은 요청을 웹 서버에 보내도록 만드는 공격
        * > 사용자의 쿠키 값을 이용하여 원하는 작업을 수행하도록 만듬.
        * */
        return http
                .csrf(csrf -> csrf.disable()) // Stateless 환경에선 CSRF 불필요
                .sessionManagement(sess -> sess
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 세션 생성 X
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**").permitAll() // 인증 없이 허용
                        .requestMatchers("/api/users/**").hasAnyAuthority( "ROLE_USER")
                        .requestMatchers("/api/admin/**").hasAnyAuthority("ROLE_ADMIN")
                        .anyRequest().authenticated()) // 나머지는 인증 필요
                /*
                * addFilterBefore
                * HttpSecurity 설정 내에서 사용되며, Spring Security의 기존 필터 체인에 사용자 정의 필터를 특정 필터 앞에 추가할 때 사용
                * */
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                /*
                * exceptionHandling
                * 설정 내에서 Spring Security가 보안 관련 예외를 처리하는 방식을 지정
                * */
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(authenticationEntryPoint) // 인증되지 않은 사용자가 보호된 리소스 접근시 처리 방식 정의
                        .accessDeniedHandler(accessDeniedHandler)) // 인증은 되었지만 인가가 허용되지 않는 사용자 처리 방식 정의
                .build();
    }
}
