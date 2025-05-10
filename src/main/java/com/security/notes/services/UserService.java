package com.security.notes.services;

import com.security.notes.dtos.UserDTO;
import com.security.notes.models.User;
import java.util.List;

public interface UserService {
    void updateUserRole(Long userId, String roleName);

    List<User> getAllUsers();

    UserDTO getUserById(Long id);

    User findByUsername(String username);
}
