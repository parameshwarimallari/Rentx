package com.rentx.carrental.exception;

public class BookingCompletedException extends RentXException {
    public BookingCompletedException(Long bookingId) {
        super("Cannot cancel completed booking with ID " + bookingId);
    }
}