package com.security.notes.security.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;
import java.time.LocalDate;
import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@Schema(description = "Response containing detailed user information.")
public class UserInfoResponse {
    @Schema(description = "User ID", example = "1")
    private Long id;

    @Schema(description = "Username", example = "johndoe")
    private String username;

    @Schema(description = "User's email", example = "johndoe@example.com")
    private String email;

    @Schema(description = "Is the account non-locked?")
    private boolean accountNonLocked;

    @Schema(description = "Is the account non-expired?")
    private boolean accountNonExpired;

    @Schema(description = "Are credentials non-expired?")
    private boolean credentialsNonExpired;

    @Schema(description = "Is the account enabled?")
    private boolean enabled;

    @Schema(description = "Credentials expiry date")
    private LocalDate credentialsExpiryDate;

    @Schema(description = "Account expiry date")
    private LocalDate accountExpiryDate;

    @Schema(description = "Is 2FA enabled?")
    private boolean isTwoFactorEnabled;

    @Schema(description = "User's roles", example = "[\"ROLE_USER\", \"ROLE_ADMIN\"]")
    private List<String> roles;
}
