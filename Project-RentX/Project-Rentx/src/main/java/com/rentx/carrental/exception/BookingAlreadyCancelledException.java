package com.rentx.carrental.exception;


public class BookingAlreadyCancelledException extends RentXException {
    public BookingAlreadyCancelledException(Long bookingId) {
        super("Booking with ID " + bookingId + " is already cancelled");
    }
}