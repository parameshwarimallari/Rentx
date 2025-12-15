package com.rentx.carrental.controller;

import com.rentx.carrental.entity.Booking;
import com.rentx.carrental.entity.Booking.RefundStatus;
import com.rentx.carrental.repository.BookingRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admin/refunds")
@RequiredArgsConstructor
public class RefundController {
    
    private final BookingRepository bookingRepository;
    
    @GetMapping("/pending")
    public ResponseEntity<List<Booking>> getPendingRefunds() {
        List<Booking> pendingRefunds = bookingRepository.findByRefundStatus(RefundStatus.PENDING);
        return ResponseEntity.ok(pendingRefunds);
    }
    
    @PostMapping("/{bookingId}/process")
    public ResponseEntity<?> processRefund(@PathVariable Long bookingId) {
        Booking booking = bookingRepository.findById(bookingId)
                .orElseThrow(() -> new RuntimeException("Booking not found"));
        
        if (booking.getRefundStatus() != RefundStatus.PENDING) {
            return ResponseEntity.badRequest().body("Refund is not in PENDING status");
        }
        
        booking.setRefundStatus(RefundStatus.PROCESSED);
        bookingRepository.save(booking);
        
        return ResponseEntity.ok().body("Refund processed successfully for booking: " + bookingId);
    }
    
    @PostMapping("/{bookingId}/fail")
    public ResponseEntity<?> failRefund(@PathVariable Long bookingId, @RequestBody Map<String, String> request) {
        Booking booking = bookingRepository.findById(bookingId)
                .orElseThrow(() -> new RuntimeException("Booking not found"));
        
        String reason = request.get("reason");
        booking.setRefundStatus(RefundStatus.FAILED);
        booking.setCancellationReason("Refund failed: " + reason);
        bookingRepository.save(booking);
        
        return ResponseEntity.ok().body("Refund marked as failed for booking: " + bookingId);
    }
    
    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getRefundStats() {
        long pendingCount = bookingRepository.countByRefundStatus(RefundStatus.PENDING);
        long processedCount = bookingRepository.countByRefundStatus(RefundStatus.PROCESSED);
        long failedCount = bookingRepository.countByRefundStatus(RefundStatus.FAILED);
        double totalPendingAmount = bookingRepository.sumRefundAmountByStatus(RefundStatus.PENDING);
        
        Map<String, Object> stats = Map.of(
            "pendingRefunds", pendingCount,
            "processedRefunds", processedCount,
            "failedRefunds", failedCount,
            "totalPendingAmount", totalPendingAmount
        );
        
        return ResponseEntity.ok(stats);
    }
}