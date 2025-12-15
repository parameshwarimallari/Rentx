package com.rentx.carrental.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.Data;
import java.time.LocalDateTime;

@Entity
@Table(name = "payment")
@Data
public class Payment {
    @Id
    private String paymentId;
    
    @Column(name = "booking_id")
    private Long bookingId; 
    
    private Double amount;
    private String currency = "INR";
    private String status; // CREATED, CAPTURED, FAILED, REFUNDED, PARTIALLY_REFUNDED
    private LocalDateTime paymentDate;
    private LocalDateTime refundDate;
    private Double refundAmount;
    private String refundId;
    private String razorpayOrderId;
    private String razorpayPaymentId;
    private String razorpaySignature;
    
    public static class PaymentStatus {
        public static final String CREATED = "CREATED";
        public static final String CAPTURED = "CAPTURED";
        public static final String FAILED = "FAILED";
        public static final String REFUNDED = "REFUNDED";
        public static final String PARTIALLY_REFUNDED = "PARTIALLY_REFUNDED";
    }
    
    @PrePersist
    protected void onCreate() {
        paymentDate = LocalDateTime.now();
    }
}