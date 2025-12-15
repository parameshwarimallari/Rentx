package com.rentx.carrental.exception;

public class EmailException extends RuntimeException {
    private final String email;
    private final String operation;

    public EmailException(String message, String email, String operation) {
        super(message);
        this.email = email;
        this.operation = operation;
    }

    public EmailException(String message, String email, String operation, Throwable cause) {
        super(message, cause);
        this.email = email;
        this.operation = operation;
    }

 
    public String getEmail() { return email; }
    public String getOperation() { return operation; }

    @Override
    public String toString() {
        return String.format("EmailException{email='%s', operation='%s', message='%s'}",
                email, operation, getMessage());
    }
}