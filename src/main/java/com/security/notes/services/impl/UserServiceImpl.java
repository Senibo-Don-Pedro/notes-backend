package com.security.notes.services.impl;

import com.security.notes.dtos.UserDTO;
import com.security.notes.models.AppRole;
import com.security.notes.models.PasswordResetToken;
import com.security.notes.models.Role;
import com.security.notes.models.User;
import com.security.notes.repositories.PasswordResetTokenRepository;
import com.security.notes.repositories.RoleRepository;
import com.security.notes.repositories.UserRepository;
import com.security.notes.services.TotpService;
import com.security.notes.services.UserService;
import com.security.notes.util.EmailService;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.UUID;


@Service
public class UserServiceImpl implements UserService {

    @Value("${frontend.url}")
    String frontendUrl;


    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final EmailService emailService;
    private final TotpService totpService;


    // Spring will auto-wire this (only one constructor → @Autowired is optional)
    @Autowired
    public UserServiceImpl(UserRepository userRepository,
                           RoleRepository roleRepository,
                           PasswordEncoder passwordEncoder,
                           PasswordResetTokenRepository passwordResetTokenRepository,
                           EmailService emailService,
                           TotpService totpService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.passwordResetTokenRepository = passwordResetTokenRepository;
        this.emailService = emailService;
        this.totpService = totpService;
    }

    @Override
    public void updateUserRole(Long userId, String roleName) {
        User user = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));

        AppRole appRole = AppRole.valueOf(roleName);

        Role role = roleRepository.findByRoleName(appRole).orElseThrow(() -> new RuntimeException("Role not found"));

        user.setRole(role);

        userRepository.save(user);
    }

    @Override
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @Override
    public UserDTO getUserById(Long id) {
//        return userRepository.findById(id).orElseThrow();
        User user = userRepository.findById(id).orElseThrow();
        return convertToDto(user);
    }

    private UserDTO convertToDto(User user) {
        return new UserDTO(
                user.getUserId(),
                user.getUserName(),
                user.getEmail(),
                user.isAccountNonLocked(),
                user.isAccountNonExpired(),
                user.isCredentialsNonExpired(),
                user.isEnabled(),
                user.getCredentialsExpiryDate(),
                user.getAccountExpiryDate(),
                user.getTwoFactorSecret(),
                user.isTwoFactorEnabled(),
                user.getSignUpMethod(),
                user.getRole(),
                user.getCreatedDate(),
                user.getUpdatedDate()
        );
    }

    @Override
    public User findByUsername(String username) {
        Optional<User> user = userRepository.findByUserName(username);
        return user.orElseThrow(() -> new RuntimeException("User not found with username: " + username));
    }

    @Override
    public void updateAccountLockStatus(Long userId, boolean lock) {
        User user = userRepository.findById(userId).orElseThrow(()
                -> new RuntimeException("User not found"));
        user.setAccountNonLocked(!lock);
        userRepository.save(user);
    }

    @Override
    public List<Role> getAllRoles() {
        return roleRepository.findAll();
    }

    @Override
    public void updateAccountExpiryStatus(Long userId, boolean expire) {
        User user = userRepository.findById(userId).orElseThrow(()
                -> new RuntimeException("User not found"));
        user.setAccountNonExpired(!expire);
        userRepository.save(user);
    }

    @Override
    public void updateAccountEnabledStatus(Long userId, boolean enabled) {
        User user = userRepository.findById(userId).orElseThrow(()
                -> new RuntimeException("User not found"));
        user.setEnabled(enabled);
        userRepository.save(user);
    }

    @Override
    public void updateCredentialsExpiryStatus(Long userId, boolean expire) {
        User user = userRepository.findById(userId).orElseThrow(()
                -> new RuntimeException("User not found"));
        user.setCredentialsNonExpired(!expire);
        userRepository.save(user);
    }

    @Override
    public void updatePassword(Long userId, String password) {
        try {
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("User not found"));
            user.setPassword(passwordEncoder.encode(password));
            userRepository.save(user);
        } catch (Exception e) {
            throw new RuntimeException("Failed to update password");
        }
    }

    @Override
    public void generatePasswordResetToken(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        String token = UUID.randomUUID().toString();

        Instant expiryDate = Instant.now().plus(24, ChronoUnit.HOURS);

        PasswordResetToken resetToken = new PasswordResetToken(token, expiryDate, user);

        passwordResetTokenRepository.save(resetToken);

        String resetUrl = String.format("%s/reset-password?token=%s",frontendUrl,token);

        //Send email to user

        emailService.sendPasswordResetEmail(user.getEmail(), resetUrl);
    }

    @Override
    public void resetPassword(String token, String newPassword) {
        PasswordResetToken resetToken = passwordResetTokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid Password Reset Token"));

        if (resetToken.isUsed()) throw new RuntimeException("Password reset token has been used");

        if (resetToken.getExpiryDate().isBefore(Instant.now())) throw new RuntimeException("Password reset token has expired");

        User user = resetToken.getUser();

        user.setPassword(passwordEncoder.encode(newPassword));

        userRepository.save(user);

        resetToken.setUsed(true);

        passwordResetTokenRepository.save(resetToken);
    }

    @Override
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Override
    public User registerUser(User newUser) {

        if(newUser.getPassword() != null)
            newUser.setPassword(passwordEncoder.encode(newUser.getPassword()));

        return userRepository.save(newUser);
    }

    @Override
    public GoogleAuthenticatorKey generate2FASecret(Long userId){
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        GoogleAuthenticatorKey key = totpService.generateSecret();
        user.setTwoFactorSecret(key.getKey());
        userRepository.save(user);
        return key;
    }

    @Override
    public boolean validate2FACode(Long userId, int code){
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        return totpService.verifyCode(user.getTwoFactorSecret(), code);
    }

    @Override
    public void enable2FA(Long userId){
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        user.setTwoFactorEnabled(true);
        userRepository.save(user);
    }

    @Override
    public void disable2FA(Long userId){
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        user.setTwoFactorEnabled(false);
        userRepository.save(user);
    }

}
