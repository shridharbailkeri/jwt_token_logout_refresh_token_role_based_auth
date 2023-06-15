package com.alibou.security;

import com.alibou.security.user.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {
    // optional is a generic type
    Optional<User> findByEmail(String email);
}
