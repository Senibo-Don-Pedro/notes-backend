package com.security.notes.security.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.*;
import lombok.Data;

import java.util.Set;

@Data
@Schema(description = "Signup request for creating a new user.")
public class SignupRequest {

    @Schema(description = "User's username", example = "johndoe", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank
    @Size(min=3, max=20)
    private String username;

    @Schema(description = "User's email address", example = "johndoe@example.com", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank
    @Size(max = 50)
    @Email
    private String email;

    @Schema(description = "User's roles (e.g., ['admin', 'user'])")
    private Set<String> role;

    @Schema(description = "User's password", example = "strongPassword123", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank
    @Size(min = 6, max = 40)
    private String password;
}
