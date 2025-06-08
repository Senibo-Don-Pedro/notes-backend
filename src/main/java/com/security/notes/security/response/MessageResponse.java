package com.security.notes.security.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Schema(description = "Generic response message for status updates or errors.")
public class MessageResponse {
    @Schema(description = "Message describing the response", example = "User registered successfully!")
    private String message;

    public MessageResponse(String message) {
        this.message = message;
    }
}
