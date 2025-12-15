package com.rentx.carrental.controller;

import java.util.List;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.rentx.carrental.dto.BookingResponse;
import com.rentx.carrental.service.BookingService;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/pickups")
@RequiredArgsConstructor
public class PickupController {
    
    private final BookingService bookingService;
    
    @PostMapping("/{bookingId}/pickup")
    public ResponseEntity<?> markAsPickedUp(@PathVariable Long bookingId, 
                                           @RequestBody Map<String, String> request) {
        return ResponseEntity.ok("Pickup endpoint - Coming soon!");
    }
    
    @PostMapping("/{bookingId}/return")
    public ResponseEntity<?> markAsReturned(@PathVariable Long bookingId,
                                           @RequestBody Map<String, Object> request) {
        return ResponseEntity.ok("Return endpoint - Coming soon!");
    }
    
    @GetMapping("/active")
    public ResponseEntity<List<BookingResponse>> getActiveBookings() {
        return ResponseEntity.ok(List.of()); 
    }
}