package com.rentx.carrental.dto;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.time.LocalDateTime;

@Data
public class BookingRequest {
    @NotNull(message = "Car ID is required")
    private Long carId;
    
    @NotNull(message = "Start date is required")
   @Future(message = "Start date must be in the future")
    private LocalDateTime startDate;
    
    @NotNull(message = "End date is required")
   @Future(message = "End date must be in the future")
    private LocalDateTime endDate;
    
    private String paymentOption;
    
    @AssertTrue(message = "End date must be after start date")
    private boolean isEndDateAfterStartDate() {
        return endDate != null && startDate != null && endDate.isAfter(startDate);
    }
}
