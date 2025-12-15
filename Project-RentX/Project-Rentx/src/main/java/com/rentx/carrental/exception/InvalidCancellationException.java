package com.rentx.carrental.exception;

public class InvalidCancellationException extends RentXException {
    public InvalidCancellationException(Long bookingId) {
        super("Only confirmed bookings can be cancelled. Booking ID: " + bookingId);
    }
}
