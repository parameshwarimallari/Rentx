package com.rentx.carrental.exception;

public class SqlInjectionAttemptException extends RentXException {
    
    public SqlInjectionAttemptException() {
        super("Invalid input detected");
    }
    
    public SqlInjectionAttemptException(String message) {
        super(message);
    }
    
    public SqlInjectionAttemptException(String message, Throwable cause) {
        super(message, cause);
    }
}