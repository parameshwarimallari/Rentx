package com.rentx.carrental.exception;

public class CarNotFoundException extends RentXException {
    public CarNotFoundException(Long carId) {
        super("Car not found with ID: " + carId);
    }
    
    public CarNotFoundException(String message) {
        super(message);
    }
}


