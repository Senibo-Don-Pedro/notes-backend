package com.security.notes.controllers;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(
        name = "CSRF",
        description = "Endpoint for retrieving CSRF token"
)
@RestController
public class CsrfController {

    @Operation(
            summary = "Get CSRF token",
            description = "Returns the CSRF token for the current session (useful for frontend clients)."
    )
    @ApiResponse(
            responseCode = "200",
            description = "CSRF token retrieved successfully",
            content = @Content(schema = @Schema(implementation = org.springframework.security.web.csrf.CsrfToken.class))
    )
    @GetMapping("/api/csrf-token")
    public CsrfToken csrfToken(HttpServletRequest request) {
        return (CsrfToken) request.getAttribute(CsrfToken.class.getName());
    }
}
