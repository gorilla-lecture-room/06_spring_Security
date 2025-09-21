package com.ohgiraffers.securitysession;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@EntityScan(basePackages = "com.ohgiraffers.securitysession.user.model.entity")
@EnableJpaRepositories(basePackages = "com.ohgiraffers.securitysession.user.repository")
public class Chap08SecuritySessionApplication {

    public static void main(String[] args) {
        SpringApplication.run(Chap08SecuritySessionApplication.class, args);
    }

}
