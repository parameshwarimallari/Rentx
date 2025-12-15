package com.rentx.carrental.exception;

public class UserNotFoundException extends RentXException {
    public UserNotFoundException(String username) {
        super("User not found: " + username);
    }
    
    public UserNotFoundException(Long userId) {
        super("User not found with ID: " + userId);
    }
}