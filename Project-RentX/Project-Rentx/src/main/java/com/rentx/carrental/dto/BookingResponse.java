package com.rentx.carrental.dto;

import java.time.LocalDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
public class BookingResponse {
    private Long id;
    private Long carId;
    private String carBrand;
    private String carModel;
    private String carImage;
    private LocalDateTime startDate;
    private LocalDateTime endDate;
    private Double totalPrice;
    private LocalDateTime bookingDate;
    private String status;
    private Integer totalDays;
    private Double discountAmount;
    private Double refundAmount;
    private String cancellationReason;
    private LocalDateTime cancellationDate;
    private String refundStatus;
    private String paymentStatus; 
    private String pickupStatus;
    private Double extraCharges;
    private LocalDateTime actualPickupTime;
    private Double lateReturnPenalty;
    private Boolean isLateReturn;
    private LocalDateTime actualReturnTime;
}