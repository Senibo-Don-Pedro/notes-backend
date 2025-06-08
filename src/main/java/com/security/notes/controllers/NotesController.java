package com.security.notes.controllers;

import com.security.notes.models.Note;
import com.security.notes.services.NoteService;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;



@Tag(
        name = "Notes",
        description = "Endpoints for creating, viewing, updating, and deleting user notes"
)
@SecurityRequirement(name = "bearerAuth")
@RestController
@RequestMapping("/api/notes")
public class NotesController {


    private final NoteService noteService;

    public NotesController(NoteService noteService) {
        this.noteService = noteService;
    }


    @Operation(
            summary = "Create a new note",
            description = "Creates a new note for the authenticated user and returns the created note."
    )
    @ApiResponse(
            responseCode = "200",
            description = "Note created successfully",
            content = @Content(schema = @Schema(implementation = Note.class))
    )
    @PostMapping
    public Note createNote(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Note content as plain text", required = true,
                    content = @Content(schema = @Schema(type = "string", example = "My new note"))
            )
            @RequestBody String content,

            @Parameter(hidden = true)
            @AuthenticationPrincipal UserDetails userDetails) {
        String username = userDetails.getUsername();
        System.out.println("USER DETAILS: " + username);
        return noteService.createNoteForUser(username, content);
    }



    @Operation(
            summary = "Get user notes",
            description = "Returns all notes belonging to the authenticated user."
    )
    @ApiResponse(
            responseCode = "200",
            description = "List of user notes",
            content = @Content(array = @ArraySchema(schema = @Schema(implementation = Note.class)))
    )
    @GetMapping
    public List<Note> getUserNotes(
            @Parameter(hidden = true)
            @AuthenticationPrincipal UserDetails userDetails) {
        String username = userDetails.getUsername();
        System.out.println("USER DETAILS: " + username);
        return noteService.getNotesForUser(username);
    }


    @Operation(
            summary = "Update a note",
            description = "Updates the content of a note for the authenticated user."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Note updated",
                    content = @Content(schema = @Schema(implementation = Note.class))),
            @ApiResponse(responseCode = "404", description = "Note not found")
    })
    @PutMapping("/{noteId}")
    public Note updateNote(
            @Parameter(description = "ID of the note to update", required = true)
            @PathVariable Long noteId,
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Updated note content as plain text", required = true,
                    content = @Content(schema = @Schema(type = "string", example = "Updated note content"))
            )
            @RequestBody String content,
            @Parameter(hidden = true) @AuthenticationPrincipal UserDetails userDetails
    ) {
        String username = userDetails.getUsername();
        return noteService.updateNoteForUser(noteId, content, username);

    }

    @Operation(
            summary = "Delete a note",
            description = "Deletes a note belonging to the authenticated user."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Note deleted"),
            @ApiResponse(responseCode = "404", description = "Note not found")
    })
    @DeleteMapping("/{noteId}")
    public void deleteNote(
            @Parameter(description = "ID of the note to delete", required = true)
            @PathVariable Long noteId,
            @Parameter(hidden = true) @AuthenticationPrincipal UserDetails userDetails
    ) {
        String username = userDetails.getUsername();
        noteService.deleteNoteForUser(noteId, username);
    }
}
