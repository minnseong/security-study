package com.ms.securitystudy.repository;

import com.ms.securitystudy.entity.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    @EntityGraph(attributePaths = "authorities") // lazy 조회가 아닌 eager 조회로 authorities 가져온다
    Optional<User> findOneWithAuthoritiesByUsername(String username);
}

