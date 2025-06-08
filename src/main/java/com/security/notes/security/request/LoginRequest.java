package com.security.notes.security.request;


import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;

@Getter
@Setter
@Schema(description = "Login request containing username and password.")
public class LoginRequest {
    @Schema(description = "User's username", example = "johndoe")
    private String username;

    @Schema(description = "User's password", example = "strongPassword123")
    private String password;
}
