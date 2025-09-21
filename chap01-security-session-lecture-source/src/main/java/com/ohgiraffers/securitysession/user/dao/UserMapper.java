package com.ohgiraffers.securitysession.user.dao;

import com.ohgiraffers.securitysession.user.model.dto.LoginUserDTO;
import com.ohgiraffers.securitysession.user.model.dto.SignupDTO;
import org.apache.ibatis.annotations.Mapper;

/**
 * 이 파일은 레거시 MyBatis 코드입니다.
 * JPA로 마이그레이션되었으며, 참조용으로 보존합니다.
 */
//@Mapper
public interface UserMapper {

    int regist(SignupDTO signupDTO);

    LoginUserDTO findByUsername(String username);
}
