package com.security.notes.dtos;

import com.security.notes.models.Role;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.time.LocalDateTime;
import io.swagger.v3.oas.annotations.media.Schema;


@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "DTO representing a user and their account details.")
public class UserDTO {
    @Schema(description = "Unique ID of the user", example = "1")
    private Long userId;

    @Schema(description = "Username", example = "john_doe")
    private String userName;

    @Schema(description = "User email address", example = "john@example.com")
    private String email;

    @Schema(description = "Is the account non-locked?")
    private boolean accountNonLocked;

    @Schema(description = "Is the account non-expired?")
    private boolean accountNonExpired;

    @Schema(description = "Are the credentials non-expired?")
    private boolean credentialsNonExpired;

    @Schema(description = "Is the account enabled?")
    private boolean enabled;

    @Schema(description = "Credentials expiry date")
    private LocalDate credentialsExpiryDate;

    @Schema(description = "Account expiry date")
    private LocalDate accountExpiryDate;

    @Schema(description = "2FA secret (should be hidden in production)")
    private String twoFactorSecret;

    @Schema(description = "Is two-factor authentication enabled?")
    private boolean isTwoFactorEnabled;

    @Schema(description = "How the user signed up (e.g., 'email', 'google')")
    private String signUpMethod;

    @Schema(description = "User's role")
    private Role role;

    @Schema(description = "Account creation date/time")
    private LocalDateTime createdDate;

    @Schema(description = "Account last update date/time")
    private LocalDateTime updatedDate;
}
