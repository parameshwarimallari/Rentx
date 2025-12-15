package com.rentx.carrental.exception;

public class EmailSendingException extends EmailException {
    private final String subject;
    private final String templateType;

    public EmailSendingException(String message, String email, String operation, 
                               String subject, String templateType) {
        super(message, email, operation);
        this.subject = subject;
        this.templateType = templateType;
    }

    public EmailSendingException(String message, String email, String operation, 
                               String subject, String templateType, Throwable cause) {
        super(message, email, operation, cause);
        this.subject = subject;
        this.templateType = templateType;
    }

    
    public String getSubject() { return subject; }
    public String getTemplateType() { return templateType; }

    @Override
    public String toString() {
        return String.format("EmailSendingException{email='%s', operation='%s', " +
                           "subject='%s', templateType='%s', message='%s'}",
                getEmail(), getOperation(), subject, templateType, getMessage());
    }
}