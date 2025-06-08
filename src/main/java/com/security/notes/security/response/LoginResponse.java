package com.security.notes.security.response;



import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@Schema(description = "Response returned after successful login containing JWT and user details.")
public class LoginResponse {
    @Schema(description = "JWT token to be used in Authorization header", example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
    private String jwtToken;

    @Schema(description = "User's username", example = "johndoe")
    private String username;

    @Schema(description = "User's roles", example = "[\"ROLE_USER\", \"ROLE_ADMIN\"]")
    private List<String> roles;
}
