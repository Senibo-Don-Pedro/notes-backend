package com.security.notes.controllers;

import com.security.notes.models.AuditLog;
import com.security.notes.services.AuditLogService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;


@Tag(
        name = "Audit Logs",
        description = "Endpoints for viewing application audit logs. Admin access required."
)
@SecurityRequirement(name = "bearerAuth")
@RestController
@RequestMapping("/api/audit")
public class AuditLogController {
    private final AuditLogService auditLogService;

    public AuditLogController(AuditLogService auditLogService) {
        this.auditLogService = auditLogService;
    }


    @Operation(
            summary = "Get all audit logs",
            description = "Retrieve a list of all audit log entries. Admin access required."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = AuditLog.class))))
    })
    @GetMapping
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public List<AuditLog> getAuditLogs(){
        return auditLogService.getAllAuditLogs();
    }



    @Operation(
            summary = "Get audit logs for a note",
            description = "Retrieve all audit logs related to a specific note by its ID. Admin access required."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = AuditLog.class))))
    })
    @GetMapping("/note/{id}")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public List<AuditLog> getNoteAuditLogs(
            @Parameter(description = "ID of the note", required = true)
            @PathVariable Long id
    ){
        return auditLogService.getAuditLogsForNoteId(id);
    }
}
