package com.ohgiraffers.securitysession.user.service;

import com.ohgiraffers.securitysession.common.UserRole;
import com.ohgiraffers.securitysession.user.model.dto.LoginUserDTO;
import com.ohgiraffers.securitysession.user.model.dto.SignupDTO;
import com.ohgiraffers.securitysession.user.model.entity.User;
import com.ohgiraffers.securitysession.user.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
public class MemberService {

    private final UserRepository userRepository;
    private final PasswordEncoder encoder;

    @Autowired
    public MemberService(UserRepository userRepository, PasswordEncoder encoder) {
        this.userRepository = userRepository;
        this.encoder = encoder;
    }

    @Transactional
    public Integer regist(SignupDTO signupDTO) {
        // 중복 아이디 체크
        if (userRepository.existsByUserId(signupDTO.getUserId())) {
            return null; // 중복된 아이디가 존재함을 null로 표시
        }
        
        try {
            // DTO를 엔티티로 변환
            User user = new User();
            user.setUserId(signupDTO.getUserId());
            user.setUserName(signupDTO.getUserName());
            user.setPassword(encoder.encode(signupDTO.getUserPass()));
            user.setUserRole(UserRole.valueOf(signupDTO.getRole()));
            
            // 저장 후 생성된 사용자 코드 반환
            User savedUser = userRepository.save(user);
            return savedUser.getUserCode();
        } catch (Exception e) {
            e.printStackTrace();
            return 0; // 서버 오류를 0으로 표시
        }
    }

    /**
     * 사용자의 id를 입력받아 DB에서 회원을 조회하는 메서드
     * @param username : 사용자 id
     * @return LoginUserDTO : LoginUserDTO 사용자 개체
     */
    public LoginUserDTO findByUsername(String username) {
        Optional<User> userOptional = userRepository.findByUserId(username);
        
        // 엔티티를 DTO로 변환
        return userOptional.map(user -> new LoginUserDTO(
                user.getUserCode(),
                user.getUserId(),
                user.getUserName(),
                user.getPassword(),
                user.getUserRole()
        )).orElse(null);
    }
}
