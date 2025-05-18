package com.security.notes.services.impl;

import com.security.notes.models.Note;
import com.security.notes.repositories.NoteRepository;
import com.security.notes.services.AuditLogService;
import com.security.notes.services.NoteService;
import org.aspectj.weaver.ast.Not;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class NoteServiceImpl implements NoteService {
    private final NoteRepository noteRepository;
    private final AuditLogService auditLogService;

    public NoteServiceImpl(NoteRepository noteRepository, AuditLogService auditLogService) {
        this.noteRepository = noteRepository;
        this.auditLogService = auditLogService;
    }


    @Override
    public Note createNoteForUser(String username, String content) {
        Note note = new Note();
        note.setContent(content);
        note.setOwnerUsername(username);

        // Save first to generate ID
        Note savedNote = noteRepository.save(note);

        // Now the ID is available
        auditLogService.logNoteCreation(username, savedNote);

        return savedNote;

    }

    @Override
    public Note updateNoteForUser(Long noteId, String content, String username) {
        Note note = noteRepository.findById(noteId).orElseThrow(() -> new RuntimeException("Note not found"));

        note.setContent(content);
        auditLogService.logNoteUpdate(username, note);

        return noteRepository.save(note);
    }

    @Override
    public void deleteNoteForUser(Long noteId, String username) {
        Note note = noteRepository.findById(noteId).orElseThrow(
                () -> new RuntimeException("Note not found")
        );


        auditLogService.logNoteDeletion(username, noteId);
        noteRepository.delete(note);
    }

    @Override
    public List<Note> getNotesForUser(String username) {

        return noteRepository.findByOwnerUsername(username);
    }
}
