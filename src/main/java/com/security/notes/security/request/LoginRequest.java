package com.security.notes.security.request;


import lombok.*;

@Getter
@Setter
public class LoginRequest {
    private String username;
    private String password;
}
