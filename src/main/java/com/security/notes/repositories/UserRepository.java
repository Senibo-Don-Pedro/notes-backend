package com.security.notes.repositories;

import com.security.notes.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUserName(String username);

    Boolean existsByEmail(String email);
    Boolean existsByUserName(String username);

    Optional<User> findByEmail(String email);
}
