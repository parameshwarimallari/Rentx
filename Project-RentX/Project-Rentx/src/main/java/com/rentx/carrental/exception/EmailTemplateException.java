package com.rentx.carrental.exception;

public class EmailTemplateException extends EmailException {
    private final String templateName;
    private final Object templateData;

    public EmailTemplateException(String message, String email, String operation, 
                                String templateName, Object templateData) {
        super(message, email, operation);
        this.templateName = templateName;
        this.templateData = templateData;
    }

    public EmailTemplateException(String message, String email, String operation, 
                                String templateName, Object templateData, Throwable cause) {
        super(message, email, operation, cause);
        this.templateName = templateName;
        this.templateData = templateData;
    }

    public String getTemplateName() { return templateName; }
    public Object getTemplateData() { return templateData; }

    @Override
    public String toString() {
        return String.format("EmailTemplateException{email='%s', operation='%s', " +
                           "templateName='%s', message='%s'}",
                getEmail(), getOperation(), templateName, getMessage());
    }
}