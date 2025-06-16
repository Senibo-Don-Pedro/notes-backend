package com.security.notes.controllers;

import com.security.notes.models.AppRole;
import com.security.notes.models.Role;
import com.security.notes.models.User;
import com.security.notes.repositories.RoleRepository;
import com.security.notes.repositories.UserRepository;
import com.security.notes.security.jwt.JwtUtils;
import com.security.notes.security.request.LoginRequest;
import com.security.notes.security.request.SignupRequest;
import com.security.notes.security.response.LoginResponse;
import com.security.notes.security.response.MessageResponse;
import com.security.notes.security.response.UserInfoResponse;
import com.security.notes.security.services.UserDetailsImpl;
import com.security.notes.services.TotpService;
import com.security.notes.services.UserService;
import com.security.notes.util.AuthUtil;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;



@Tag(
        name = "Authentication",
        description = "Endpoints for user registration, login, and authentication management"
)
@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "${frontend.url}",
        maxAge = 3600,
        allowCredentials = "true")
public class AuthController {

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    UserService userService;

    @Autowired
    AuthUtil authUtil;

    @Autowired
    TotpService totpService;


    @Operation(
            summary = "Authenticate user (login)",
            description = "Authenticate user and return a JWT token, username, and roles."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful authentication",
                    content = @Content(schema = @Schema(implementation = LoginResponse.class))),
            @ApiResponse(responseCode = "404", description = "Bad credentials",
                    content = @Content(schema = @Schema(implementation = MessageResponse.class)))
    })
    @PostMapping("/public/signin")
    public ResponseEntity<?> authenticateUser(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "User login details (username and password)",
                    required = true,
                    content = @Content(schema = @Schema(implementation = LoginRequest.class))
            )
            @RequestBody LoginRequest loginRequest) {
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),
                            loginRequest.getPassword()));
        } catch (AuthenticationException exception) {
            Map<String, Object> map = new HashMap<>();
            map.put("message", "Bad Credentials");
            map.put("status", false);
            return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
        }

        //set the authentication
        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

        // Collect roles from the UserDetails
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        // Prepare the response body, now including the JWT token directly in the body
        LoginResponse response = new LoginResponse(jwtToken, userDetails.getUsername(), roles);

        // Return the response entity with the JWT token included in the response body
        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Register a new user",
            description = "Create a new user account."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User registered successfully",
                    content = @Content(schema = @Schema(implementation = MessageResponse.class))),
            @ApiResponse(responseCode = "400", description = "Username or email already exists",
                    content = @Content(schema = @Schema(implementation = MessageResponse.class)))
    })
    // AuthController.java
    @PostMapping("/public/signup")
    public ResponseEntity<?> registerUser(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Signup details (username, email, password, roles)",
                    required = true,
                    content = @Content(schema = @Schema(implementation = SignupRequest.class))
            )
            @Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUserName(signUpRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Role role;

        if (strRoles == null || strRoles.isEmpty()) {
            role = roleRepository.findByRoleName(AppRole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
        } else {
            String roleStr = strRoles.iterator().next();
            if (roleStr.equals("admin")) {
                role = roleRepository.findByRoleName(AppRole.ROLE_ADMIN)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            } else {
                role = roleRepository.findByRoleName(AppRole.ROLE_USER)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            }

            user.setAccountNonLocked(true);
            user.setAccountNonExpired(true);
            user.setCredentialsNonExpired(true);
            user.setEnabled(true);
            user.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
            user.setAccountExpiryDate(LocalDate.now().plusYears(1));
            user.setTwoFactorEnabled(false);
            user.setSignUpMethod("email");
        }
        user.setRole(role);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }


    @SecurityRequirement(name = "bearerAuth")
    @Operation(
            summary = "Get current user details",
            description = "Returns user details for the authenticated user."
    )
    @ApiResponse(responseCode = "200", description = "Current user info",
            content = @Content(schema = @Schema(implementation = UserInfoResponse.class)))
    @GetMapping("/user")
    public ResponseEntity<?> getUserDetails(@AuthenticationPrincipal UserDetails userDetails) {
        User user = userService.findByUsername(userDetails.getUsername());

        List<String> roles = userDetails
                .getAuthorities()
                .stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());


        UserInfoResponse response = new UserInfoResponse(
                user.getUserId(),
                user.getUserName(),
                user.getEmail(),
                user.isAccountNonLocked(),
                user.isAccountNonExpired(),
                user.isCredentialsNonExpired(),
                user.isEnabled(),
                user.getCredentialsExpiryDate(),
                user.getAccountExpiryDate(),
                user.isTwoFactorEnabled(),
                roles
        );

        return ResponseEntity.ok().body(response);
    }


    @SecurityRequirement(name = "bearerAuth")
    @Operation(
            summary = "Get current username",
            description = "Returns the username of the currently authenticated user."
    )
    @ApiResponse(responseCode = "200", description = "Current username",
            content = @Content(schema = @Schema(example = "{\"username\":\"john_doe\", \"status\":200, \"message\":\"OK\"}")))
    @GetMapping("/username")
    public ResponseEntity<?> currentUserName(@AuthenticationPrincipal UserDetails userDetails) {

        Map<Object, Object> map = new HashMap<>();
        map.put("username", (userDetails != null) ? userDetails.getUsername() : "");
        map.put("status", HttpStatus.OK.value());  // This adds the numeric status code (200)
        // Optionally also include the reason phrase
        map.put("message", HttpStatus.OK.getReasonPhrase());  // This adds "OK"

        return new ResponseEntity<Object>(map, HttpStatus.OK);
    }


    @Operation(
            summary = "Request password reset",
            description = "Send a password reset token to the user's email."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Reset token sent",
                    content = @Content(schema = @Schema(implementation = MessageResponse.class))),
            @ApiResponse(responseCode = "500", description = "Error sending email",
                    content = @Content(schema = @Schema(implementation = MessageResponse.class)))
    })
    @PostMapping("/public/forgot-password")
    public ResponseEntity<?> forgotPassword(
            @Parameter(description = "User's email", required = true)
            @RequestParam String email) {

        try {
            userService.generatePasswordResetToken(email);
            return ResponseEntity.ok(new MessageResponse("Password reset token sent"));
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new MessageResponse("Error sending password reset email"));
        }


    }


    @Operation(
            summary = "Reset password",
            description = "Reset the user's password using the reset token."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Password reset successfully",
                    content = @Content(schema = @Schema(implementation = MessageResponse.class))),
            @ApiResponse(responseCode = "400", description = "Invalid token or other error",
                    content = @Content(schema = @Schema(implementation = MessageResponse.class)))
    })
    @PostMapping("/public/reset-password")
    public ResponseEntity<?> resetPassword(
            @Parameter(description = "Password reset token", required = true)
            @RequestParam String token,

            @Parameter(description = "New password", required = true)
            @RequestParam String newPassword
    ) {
        try {
            userService.resetPassword(token, newPassword);
            return ResponseEntity.ok(new MessageResponse("Password Reset Successfully"));
        } catch (RuntimeException e) {

            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new MessageResponse(e.getMessage()));
        }

    }

    @SecurityRequirement(name = "bearerAuth")
    @Operation(
            summary = "Enable 2FA for user",
            description = "Generate and return 2FA QR code URL for the authenticated user."
    )
    @ApiResponse(responseCode = "200", description = "QR code URL returned")
    // 2FA Authentication
    @PostMapping("/enable-2fa")
    public ResponseEntity<String> enable2FA() {
        Long userId = authUtil.loggedInUserId();
        GoogleAuthenticatorKey secret = userService.generate2FASecret(userId);
        String qrCodeUrl = totpService.getQrCodeUrl(secret,
                userService.getUserById(userId).getUserName());
        return ResponseEntity.ok(qrCodeUrl);
    }

    @SecurityRequirement(name = "bearerAuth")
    @Operation(
            summary = "Disable 2FA for user",
            description = "Disable 2FA for the authenticated user."
    )
    @ApiResponse(responseCode = "200", description = "2FA disabled")
    @PostMapping("/disable-2fa")
    public ResponseEntity<String> disable2FA() {
        Long userId = authUtil.loggedInUserId();
        userService.disable2FA(userId);
        return ResponseEntity.ok("2FA disabled");
    }


    @SecurityRequirement(name = "bearerAuth")
    @Operation(
            summary = "Verify 2FA code",
            description = "Verify a 2FA code for the authenticated user."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "2FA verified"),
            @ApiResponse(responseCode = "401", description = "Invalid 2FA code")
    })
    @PostMapping("/verify-2fa")
    public ResponseEntity<String> verify2FA(
            @Parameter(description = "2FA verification code", required = true)
            @RequestParam int code) {
        Long userId = authUtil.loggedInUserId();
        boolean isValid = userService.validate2FACode(userId, code);
        if (isValid) {
            userService.enable2FA(userId);
            return ResponseEntity.ok("2FA Verified");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid 2FA Code");
        }
    }


    @SecurityRequirement(name = "bearerAuth")
    @Operation(
            summary = "Get 2FA status",
            description = "Check if 2FA is enabled for the authenticated user."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "2FA status"),
            @ApiResponse(responseCode = "404", description = "User not found")
    })
    @GetMapping("/user/2fa-status")
    public ResponseEntity<?> get2FAStatus() {
        User user = authUtil.loggedInUser();
        if (user != null) {
            return ResponseEntity.ok().body(Map.of("is2faEnabled", user.isTwoFactorEnabled()));
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body("User not found");
        }
    }


    @Operation(
            summary = "Verify 2FA for login",
            description = "Verify a 2FA code during the login process."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "2FA verified"),
            @ApiResponse(responseCode = "401", description = "Invalid 2FA code")
    })
    @PostMapping("/public/verify-2fa-login")
    public ResponseEntity<String> verify2FALogin(
            @Parameter(description = "2FA code", required = true)
            @RequestParam
            int code,

            @Parameter(description = "JWT token", required = true)
            @RequestParam
            String jwtToken
    ) {
        String username = jwtUtils.getUserNameFromJwtToken(jwtToken);
        User user = userService.findByUsername(username);
        boolean isValid = userService.validate2FACode(user.getUserId(), code);
        if (isValid) {
            return ResponseEntity.ok("2FA Verified");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid 2FA Code");
        }
    }


}
