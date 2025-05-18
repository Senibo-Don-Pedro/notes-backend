package com.security.notes.services.impl;

import com.security.notes.models.AuditLog;
import com.security.notes.models.Note;
import com.security.notes.repositories.AuditLogRepository;
import com.security.notes.services.AuditLogService;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class AuditLogServiceImpl implements AuditLogService {

    private final AuditLogRepository auditLogRepository;

    public AuditLogServiceImpl(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    @Override
    public void logNoteCreation(String username, Note note){
        AuditLog log = new AuditLog();

        log.setAction("CREATE");
        log.setUsername(username);
        log.setNoteId(note.getId());
        log.setNoteContent(note.getContent());
        log.setTimestamp(LocalDateTime.now());

        auditLogRepository.save(log);

    }

    @Override
    public void logNoteUpdate(String username, Note note){
        AuditLog log = new AuditLog();

        log.setAction("UPDATE");
        log.setUsername(username);
        log.setNoteId(note.getId());
        log.setNoteContent(note.getContent());
        log.setTimestamp(LocalDateTime.now());

        auditLogRepository.save(log);
    }

    @Override
    public void logNoteDeletion(String username, Long noteId){
        AuditLog log = new AuditLog();

        log.setAction("DELETE");
        log.setUsername(username);
        log.setNoteId(noteId);
        log.setTimestamp(LocalDateTime.now());

        auditLogRepository.save(log);
    }

    @Override
    public List<AuditLog> getAllAuditLogs() {
        return auditLogRepository.findAll();
    }

    @Override
    public List<AuditLog> getAuditLogsForNoteId(Long id) {
        return auditLogRepository.findByNoteId(id);
    }
}
