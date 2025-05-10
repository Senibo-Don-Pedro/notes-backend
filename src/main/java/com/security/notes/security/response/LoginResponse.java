package com.security.notes.security.response;



import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
public class LoginResponse {
    private String jwtToken;
    private String username;
    private List<String> roles;
}
