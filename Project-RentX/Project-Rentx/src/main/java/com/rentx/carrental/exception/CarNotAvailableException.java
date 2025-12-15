package com.rentx.carrental.exception;

public class CarNotAvailableException extends RentXException {
    public CarNotAvailableException(Long carId) {
        super("Car with ID " + carId + " is not available for the selected dates");
    }
}
