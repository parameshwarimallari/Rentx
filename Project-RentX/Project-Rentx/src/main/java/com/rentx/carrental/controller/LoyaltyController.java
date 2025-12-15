package com.rentx.carrental.controller;

import java.util.HashMap;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.rentx.carrental.entity.User;
import com.rentx.carrental.repository.UserRepository;
import com.rentx.carrental.service.LoyaltyService;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/loyalty")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:5173")
public class LoyaltyController {
    
    private final UserRepository userRepository;
    private final LoyaltyService loyaltyService;
    
    @GetMapping("/test/{userId}")
    public ResponseEntity<?> testLoyaltySystem(@PathVariable Long userId) {
        try {
            User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
            
            double sampleAmount = 100.0;
            long completedBookings = loyaltyService.getCompletedBookingsCount(user);
            double discount = loyaltyService.calculateDiscount(user, sampleAmount);
            String loyaltyTier = loyaltyService.getLoyaltyTier(user);
            
            Map<String, Object> response = new HashMap<>();
            response.put("user", user.getUsername());
            response.put("completedBookings", completedBookings);
            response.put("loyaltyTier", loyaltyTier);
            response.put("sampleAmount", sampleAmount);
            response.put("discountAmount", discount);
            response.put("finalAmount", sampleAmount - discount);
            response.put("discountPercentage", (discount/sampleAmount)*100 + "%");
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }
}