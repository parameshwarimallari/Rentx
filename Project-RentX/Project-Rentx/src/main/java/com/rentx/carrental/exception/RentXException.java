package com.rentx.carrental.exception;

public class RentXException extends RuntimeException {
    public RentXException(String message) {
        super(message);
    }
    
    public RentXException(String message, Throwable cause) {
        super(message, cause);
    }
}