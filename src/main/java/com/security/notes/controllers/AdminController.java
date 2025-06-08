package com.security.notes.controllers;

import com.security.notes.dtos.UserDTO;
import com.security.notes.models.Role;
import com.security.notes.models.User;
import com.security.notes.services.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;


@Tag(name = "Admin", description = "Endpoints for admin management (users, roles, account status, etc.)")
@SecurityRequirement(name = "bearerAuth")
@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ROLE_ADMIN')")
public class AdminController {
    private final UserService userService;

    @Autowired
    public AdminController(UserService userService) {
        this.userService = userService;
    }


    @Operation(summary = "Get all users", description = "Retrieve a list of all users in the system.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = User.class))))
    })
    @GetMapping("/getusers")
    public ResponseEntity<List<User>> getAllUsers() {
        return new ResponseEntity<>(userService.getAllUsers(), HttpStatus.OK);
    }


    @Operation(summary = "Update user role", description = "Update a user's role by user ID and new role name.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User role updated successfully"),
            @ApiResponse(responseCode = "400", description = "Bad request (e.g., invalid user ID or role name)")
    })
    @PutMapping("/update-role")
    public ResponseEntity<String> updateUserRole(
            @Parameter(description = "ID of the user", required = true)
            @RequestParam Long userId,

            @Parameter(description = "New role name", required = true)
            @RequestParam String roleName
    ) {
        userService.updateUserRole(userId, roleName);

        return ResponseEntity.ok("User role updated");
    }


    @Operation(summary = "Get user by ID", description = "Retrieve a user's details by their ID.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User found",
                    content = @Content(schema = @Schema(implementation = UserDTO.class))),
            @ApiResponse(responseCode = "404", description = "User not found")
    })
    @GetMapping("/user/{id}")
    public ResponseEntity<UserDTO> getUser(
            @Parameter(description = "ID of the user", required = true)
            @PathVariable Long id
    ) {
        return new ResponseEntity<>(userService.getUserById(id), HttpStatus.OK);
    }


    @Operation(summary = "Update account lock status", description = "Lock or unlock a user's account by user ID.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Account lock status updated"),
            @ApiResponse(responseCode = "400", description = "Bad request")
    })
    @PutMapping("/update-lock-status")
    public ResponseEntity<String> updateAccountLockStatus(
            @Parameter(description = "ID of the user", required = true)
            @RequestParam Long userId,

            @Parameter(description = "Lock status (true to lock, false to unlock)", required = true)
            @RequestParam boolean lock
    ) {
        userService.updateAccountLockStatus(userId, lock);
        return ResponseEntity.ok("Account lock status updated");
    }

    @Operation(summary = "Get all roles", description = "Retrieve a list of all roles in the system.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "List of roles",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = Role.class))))
    })
    @GetMapping("/roles")
    public List<Role> getAllRoles() {
        return userService.getAllRoles();
    }


    @Operation(summary = "Update account expiry status", description = "Set an account's expiry status by user ID.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Account expiry status updated"),
            @ApiResponse(responseCode = "400", description = "Bad request")
    })
    @PutMapping("/update-expiry-status")
    public ResponseEntity<String> updateAccountExpiryStatus(
            @Parameter(description = "ID of the user", required = true)
            @RequestParam Long userId,
            @Parameter(description = "Expiry status (true to expire, false otherwise)", required = true)
            @RequestParam boolean expire) {
        userService.updateAccountExpiryStatus(userId, expire);
        return ResponseEntity.ok("Account expiry status updated");
    }

    @Operation(summary = "Update account enabled status", description = "Enable or disable a user's account by user ID.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Account enabled status updated"),
            @ApiResponse(responseCode = "400", description = "Bad request")
    })
    @PutMapping("/update-enabled-status")
    public ResponseEntity<String> updateAccountEnabledStatus(
            @Parameter(description = "ID of the user", required = true)
            @RequestParam Long userId,
            @Parameter(description = "Enabled status (true to enable, false to disable)", required = true)
            @RequestParam boolean enabled) {
        userService.updateAccountEnabledStatus(userId, enabled);
        return ResponseEntity.ok("Account enabled status updated");
    }

    @Operation(summary = "Update credentials expiry status", description = "Set credentials expiry for a user.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Credentials expiry status updated"),
            @ApiResponse(responseCode = "400", description = "Bad request")
    })
    @PutMapping("/update-credentials-expiry-status")
    public ResponseEntity<String> updateCredentialsExpiryStatus(
            @Parameter(description = "ID of the user", required = true)
            @RequestParam Long userId,
            @Parameter(description = "Expiry status (true to expire, false otherwise)", required = true)
            @RequestParam boolean expire) {
        userService.updateCredentialsExpiryStatus(userId, expire);
        return ResponseEntity.ok("Credentials expiry status updated");
    }

    @Operation(summary = "Update user password", description = "Update a user's password by user ID.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Password updated successfully"),
            @ApiResponse(responseCode = "400", description = "Bad request")
    })
    @PutMapping("/update-password")
    public ResponseEntity<String> updatePassword(
            @Parameter(description = "ID of the user", required = true)
            @RequestParam Long userId,
            @Parameter(description = "New password", required = true)
            @RequestParam String password) {
        try {
            userService.updatePassword(userId, password);
            return ResponseEntity.ok("Password updated");
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }

}
