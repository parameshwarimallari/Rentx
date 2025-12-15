package com.rentx.carrental.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "booking")
@Data
public class Booking {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @JsonIgnore
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "car_id")
    private Car car;
    
    private LocalDateTime startDate;
    private LocalDateTime endDate;
    private Double totalPrice;
    private LocalDateTime bookingDate;
    private String cancellationReason;
    private LocalDateTime cancellationDate;
    
    @Column(name = "payment_status")
    private String paymentStatus = "PENDING";
    
    public static class PaymentStatus {
        public static final String PENDING = "PENDING";
        public static final String PAID = "PAID";
        public static final String PAY_AT_PICKUP = "PAY_AT_PICKUP";
        public static final String FAILED = "FAILED";
    }
    
    private Double discountAmount = 0.0;
    
    @Enumerated(EnumType.STRING)
    private BookingStatus status;
    
    private Double refundAmount = 0.0;
    
    @Enumerated(EnumType.STRING)
    private RefundStatus refundStatus = RefundStatus.NONE;
    
    @Enumerated(EnumType.STRING)
    private PickupStatus pickupStatus = PickupStatus.PENDING;
    
    private LocalDateTime actualPickupTime;
    private Double extraCharges = 0.0;
    private String pickupNotes;
    
    @PrePersist
    protected void onCreate() {
        bookingDate = LocalDateTime.now();
        if (status == null) {
            LocalDateTime now = LocalDateTime.now();
            if (now.isAfter(startDate) && now.isBefore(endDate)) {
                status = BookingStatus.ACTIVE;
            } else if (now.isAfter(endDate)) {
                status = BookingStatus.COMPLETED;
            } else {
                status = BookingStatus.CONFIRMED;
            }
        }
    }
    
    public enum BookingStatus {
        PENDING, CONFIRMED, ACTIVE, COMPLETED, CANCELLED
    }
    
    public enum RefundStatus {
        NONE, PENDING, PROCESSED, FAILED
    }
    
    public enum PickupStatus {
        PENDING, PICKED_UP, RETURNED, OVERDUE
    }
    private LocalDateTime actualReturnTime;
    private Double lateReturnPenalty = 0.0;
    private Boolean isLateReturn = false;
    public boolean isLateReturn() {
        if (actualReturnTime != null) {
            return actualReturnTime.isAfter(endDate);
        }
        return false;
    }@Column(name = "payment_method_selected")
    private String paymentMethodSelected;
    public long getLateHours() {
        if (actualReturnTime != null && actualReturnTime.isAfter(endDate)) {
            return ChronoUnit.HOURS.between(endDate, actualReturnTime);
        }
        return 0;
    }
    public int getTotalDays() {
        if (startDate == null || endDate == null) {
            return 0;
        }
        long hours = ChronoUnit.HOURS.between(startDate, endDate);
        double days = Math.ceil(hours / 24.0);
        days = Math.max(1, days);
        return (int) days;
    }
    public int getLateDays() {
        if (actualReturnTime == null || endDate == null) {
            return 0;
        }
        
        if (actualReturnTime.isAfter(endDate)) {
            long hours = ChronoUnit.HOURS.between(endDate, actualReturnTime);
            double days = Math.ceil(hours / 24.0);
            return (int) days;
        }
        return 0;
    }
}