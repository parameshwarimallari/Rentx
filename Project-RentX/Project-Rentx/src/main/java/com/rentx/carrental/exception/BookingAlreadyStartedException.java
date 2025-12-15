package com.rentx.carrental.exception;

public class BookingAlreadyStartedException extends RentXException {
    public BookingAlreadyStartedException(Long bookingId) {
        super("Cannot cancel booking with ID " + bookingId + " that has already started");
    }
}