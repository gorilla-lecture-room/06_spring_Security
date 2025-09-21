package com.ohgiraffers.security.auth.service;

import com.ohgiraffers.security.auth.model.CustomUserPrincipal;
import com.ohgiraffers.security.domain.user.entity.User;
import com.ohgiraffers.security.domain.user.model.Role;
import com.ohgiraffers.security.domain.user.service.UserService;
import jakarta.transaction.Transactional;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;


// ✅ 핵심 개념 요약
/*
- 인증된 사용자의 정보를 클라이언트가 필요로 할 때, 서버는 현재 로그인한 사용자의 ID, 역할, 이메일 등을 응답해야 함
- Spring Security는 `SecurityContextHolder`에 인증 객체를 저장하고, 이 인증 객체에서 사용자 정보를 추출할 수 있음
- 가장 실무적으로 많이 쓰이는 방식은 `@AuthenticationPrincipal`로 `UserDetails` 또는 커스텀 유저 객체를 컨트롤러에서 직접 주입받는 방식임
*/

/*******************************************
 📘 1. UserDetailsService 구현체 - 인증 정보 구성
 ********************************************/
@Service
public class CustomUserDetailsService implements UserDetailsService {


    private final UserService userService; // 🔁 userRepository → userService

    public CustomUserDetailsService(UserService userService) {
        this.userService = userService;
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = userService.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + username));

        // User 엔티티의 List<Role>을 Collection<? extends GrantedAuthority>로 변환
        Collection<? extends GrantedAuthority> authorities = mapRolesToAuthorities(user.getRoles());

        return new CustomUserPrincipal(user.getId(), user.getUsername(), user.getPassword(), authorities);
    }


    // 사용자 권한 정보 분리
    private Collection<? extends GrantedAuthority> mapRolesToAuthorities(List<Role> roles) {
        if (roles == null || roles.isEmpty()) {
            return Collections.emptyList(); // 역할이 없으면 빈 권한 목록 반환
        }

        // 각 Role Enum의 이름(예: "ROLE_USER")을 사용하여 SimpleGrantedAuthority 객체를 생성
        // Role Enum의 name() 메소드가 "ROLE_" 접두사를 포함한 문자열을 반환한다고 가정
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.name()))
                .collect(Collectors.toList()); // 또는 Collectors.toSet()
    }
}