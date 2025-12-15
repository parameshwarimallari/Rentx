package com.rentx.carrental.exception;

public class PaymentVerificationException extends PaymentException {
    public PaymentVerificationException(String message) {
        super("Payment verification failed: " + message);
    }

    public PaymentVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}