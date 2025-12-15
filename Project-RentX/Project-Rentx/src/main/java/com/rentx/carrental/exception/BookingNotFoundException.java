package com.rentx.carrental.exception;

public class BookingNotFoundException extends RentXException {
    public BookingNotFoundException(Long bookingId) {
        super("Booking not found with ID: " + bookingId);
    }
}
