package com.ohgiraffers.security.domain.user.entity;

import com.ohgiraffers.security.domain.user.model.Role;
import jakarta.persistence.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Entity
@Table(name = "jwt_login")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(unique = true)
    private String email;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "role")
    @Enumerated(EnumType.STRING)
    private List<Role> roles = new ArrayList<>();


    protected User() {
    }

    /**
     * 빌더(Builder)를 통해 객체를 생성하기 위한 private 생성자입니다.
     * Builder 클래스 내부에서만 호출됩니다.
     *
     * @param builder User 객체 생성을 위한 데이터를 담고 있는 Builder 인스턴스
     */
    private User(Builder builder) {
        this.username = builder.username;
        this.password = builder.password;
        this.email = builder.email;
        this.roles = (builder.roles != null) ? new ArrayList<>(builder.roles) : new ArrayList<>();
    }

    /**
     * User 객체를 생성하기 위한 빌더 인스턴스를 반환하는 정적 팩토리 메소드.
     *
     * @return 새로운 Builder 인스턴스
     */
    public static Builder builder() {
        return new Builder();
    }

    // --- Getter 메소드들 ---
    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getEmail() {
        return email;
    }

    /**
     * 사용자의 역할(들)을 담은 List를 반환합니다.
     *
     * @return List<Role> 역할 리스트
     */
    public List<Role> getRoles() {
        return roles;
    }
    

    // 권한 리스트 반환
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> authorities = this.roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.name()))
                .collect(Collectors.toList());
        
        return authorities;
    }
    

    @Override
    public String toString() {
        // 역할 목록을 보기 좋게 문자열로 변환
        String rolesString = (roles != null) ?
                roles.stream().map(Role::name).collect(Collectors.joining(", ")) : "[]";

        return "User{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", password='[PROTECTED]'" + // 비밀번호는 로그 출력 시 보호
                ", email='" + email + '\'' +
                ", roles=[" + rolesString + "]" + // 역할 목록 출력 방식 변경
                '}';
    }

    /**
     * User 객체 생성을 위한 정적 내부 빌더 클래스입니다.
     */
    public static class Builder {
        private String username;
        private String password;
        private String email; // email 필드 추가 (선택적 필드에서 필수 필드로 이동 가능성 고려)
        private List<Role> roles = new ArrayList<>(); // 여러 역할을 담기 위해 List로 변경 및 초기화

        /**
         * 빌더의 기본 생성자입니다.
         * User.builder()를 통해 접근합니다.
         */
        private Builder() {
        }

        public Builder username(String username) {
            this.username = username;
            return this;
        }

        public Builder password(String password) {
            this.password = password;
            return this;
        }

        public Builder email(String email) {
            this.email = email;
            return this;
        }

        /**
         * 역할 리스트 전체를 설정합니다. 기존 빌더의 역할들은 대체
         *
         * @param roles 설정할 역할 리스트
         * @return Builder 인스턴스
         */
        public Builder roles(List<Role> roles) {
            if (roles != null) {
                this.roles = new ArrayList<>(roles); // 안전하게 복사본 사용
            } else {
                this.roles = new ArrayList<>(); // null일 경우 빈 리스트로 초기화
            }
            return this;
        }

        /**
         * 단일 역할을 빌더의 역할 리스트에 추가.
         *
         * @param roles 추가할 역할
         * @return Builder 인스턴스
         */
        public Builder role(List<Role> roles) { // 메소드명 'role'로 단일 역할 추가 기능 유지
            if (roles != null || !roles.isEmpty()) {
                this.roles.addAll(roles);
            }
            return this;
        }

        /**
         * 설정된 값들을 바탕으로 최종 User 객체를 생성하여 반환
         * 필수 값들이 설정되었는지 검증합
         *
         * @return 생성된 User 객체
         */
        public User build() {
            // 필수 값 검증
            if (username == null || username.trim().isEmpty()) {
                throw new IllegalStateException("사용자 이름은 필수입니다.");
            }
            if (password == null || password.trim().isEmpty()) {
                throw new IllegalStateException("비밀번호는 필수입니다.");
            }
            if (email == null || email.trim().isEmpty()) { // email 필수 검증 유지
                throw new IllegalStateException("이메일은 필수입니다.");
            }
            if (roles == null || roles.isEmpty()) { // 역할 리스트가 비어있는지 확인
                // 애플리케이션 정책에 따라 기본 역할을 부여하거나 예외를 발생시킬 수 있습니다.
                // 여기서는 최소 하나 이상의 역할이 필수라고 가정하고 예외를 발생시킵니다.
                throw new IllegalStateException("역할은 최소 하나 이상 필수입니다.");
                // 또는 기본 역할 부여: this.roles.add(Role.ROLE_USER);
            }
            return new User(this);
        }
    }
}
