package com.rentx.carrental.controller;

import com.rentx.carrental.dto.BookingResponse;
import com.rentx.carrental.dto.UserDTO;
import com.rentx.carrental.entity.AdminRequest;
import com.rentx.carrental.entity.Booking;
import com.rentx.carrental.entity.User;
import com.rentx.carrental.repository.AdminRequestRepository;
import com.rentx.carrental.repository.BookingRepository;
import com.rentx.carrental.repository.CarRepository;
import com.rentx.carrental.repository.UserRepository;
import com.rentx.carrental.service.AdminRequestService;
import com.rentx.carrental.service.BookingService;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController 
@RequestMapping("/api/admin") 
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:5173")
public class AdminController {
    private final AdminRequestRepository adminRequestRepository;
    private final AdminRequestService adminRequestService;
private final  BookingService bookingService;
private final  UserRepository userRepository;
private final  CarRepository  carRepository;
private final BookingRepository bookingRepository;
    @GetMapping("/requests")
    public ResponseEntity<List<AdminRequest>> getAllAdminRequests() {
        try {
            List<AdminRequest> allRequests = adminRequestRepository.findAll();
            return ResponseEntity.ok(allRequests);
        } catch (Exception e) {
            return ResponseEntity.status(500).body(null);
        }
    }


    @GetMapping("/requests/user/name/{username}")
    public ResponseEntity<List<AdminRequest>> getAdminRequestsByUsername(@PathVariable String username) {
        try {
            List<AdminRequest> userRequests = adminRequestRepository.findByUserUsername(username);
            return ResponseEntity.ok(userRequests);
        } catch (Exception e) {
            return ResponseEntity.status(500).body(null);
        }
    }
    @GetMapping("/pending-requests")
    public ResponseEntity<List<AdminRequest>> getPendingRequests() {
        try {
            System.out.println("📥 Received request for /api/admin/pending-requests");
            List<AdminRequest> pendingRequests = adminRequestRepository.findByStatusOrderByRequestedAtDesc(AdminRequest.RequestStatus.PENDING);
            System.out.println("✅ Found " + pendingRequests.size() + " pending requests");
            return ResponseEntity.ok(pendingRequests);
        } catch (Exception e) {
            System.err.println("❌ Error in /api/admin/pending-requests: " + e.getMessage());
            return ResponseEntity.status(500).body(null);
        }
    }
    @PostMapping("/requests/{requestId}/action")
    public ResponseEntity<?> processAdminRequest(@PathVariable Long requestId, 
                                               @RequestBody Map<String, String> request) {
        try {
            System.out.println("🎯 POST /api/admin/requests/" + requestId + "/action called");
            String action = request.get("action");
            String notes = request.get("notes");
            AdminRequest processedRequest = adminRequestService.processAdminRequest(requestId, action, notes);
            return ResponseEntity.ok(processedRequest);
        } catch (Exception e) {
            System.err.println("❌ Error in processAdminRequest: " + e.getMessage());
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
//  
    @GetMapping("/requests/user/{userId}")
    public ResponseEntity<List<AdminRequest>> getAdminRequestsByUserId(@PathVariable Long userId) {
        try {
            System.out.println("🎯 GET /api/admin/requests/user/" + userId + " called");
            List<AdminRequest> userRequests = adminRequestRepository.findByUserId(userId);
            return ResponseEntity.ok(userRequests);
        } catch (Exception e) {
            System.err.println("❌ Error in getAdminRequestsByUserId: " + e.getMessage());
            return ResponseEntity.status(500).body(null);
        }
    }

@GetMapping("/test")
public ResponseEntity<String> testEndpoint() {
    System.out.println("✅ AdminController is working!");
    return ResponseEntity.ok("AdminController is working properly!");
}
@GetMapping("/users")
@PreAuthorize("hasRole('ADMIN')")
public ResponseEntity<List<UserDTO>> getAllUsers() {
    List<User> users = userRepository.findAll();
    List<UserDTO> userDTOs = users.stream()
            .map(this::convertToUserDTO)
            .collect(Collectors.toList());
    return ResponseEntity.ok(userDTOs);
}

private BookingResponse convertToBookingResponse(Booking booking) {
    double discount = booking.getDiscountAmount() != null ? 
        booking.getDiscountAmount() : 0.0;
    return bookingService.convertToResponse(booking, discount);
}

@GetMapping("/bookings")
@PreAuthorize("hasRole('ADMIN')")
public ResponseEntity<List<BookingResponse>> getAllBookings() {
    List<Booking> bookings = bookingRepository.findAll();
    
    List<BookingResponse> responses = bookings.stream()
        .map(this::convertToBookingResponse)
        .collect(Collectors.toList());
    
    return ResponseEntity.ok(responses);
}
private UserDTO convertToUserDTO(User user) {
    UserDTO dto = new UserDTO();
    dto.setId(user.getId());
    dto.setUsername(user.getUsername());
    dto.setEmail(user.getEmail());
    dto.setFirstName(user.getFirstName());
    dto.setLastName(user.getLastName());
    dto.setPhoneNumber(user.getPhoneNumber());
    dto.setRole(user.getRole().name());
    dto.setCreatedAt(user.getCreatedAt());
    return dto;
}


@PostConstruct
public void init() {
    System.out.println("✅ AdminController initialized!");
    System.out.println("✅ Endpoints registered:");
    System.out.println("   - GET /api/admin/pending-requests");
    System.out.println("   - POST /api/admin/requests/{requestId}/action"); 
    System.out.println("   - GET /api/admin/requests");
    System.out.println("   - GET /api/admin/requests/user/{userId}");
}
@GetMapping("/stats")
@PreAuthorize("hasRole('ADMIN')")
public ResponseEntity<Map<String, Object>> getAdminStats() {
    Map<String, Object> stats = new HashMap<>();
    
    long totalUsers = userRepository.count();
    long adminUsers = userRepository.countByRole(User.UserRole.ADMIN);
    long regularUsers = totalUsers - adminUsers;
    
    long totalBookings = bookingRepository.count();
    long confirmedBookings = bookingRepository.countByStatus(Booking.BookingStatus.CONFIRMED);
    long activeBookings = bookingRepository.countByStatus(Booking.BookingStatus.ACTIVE);
    long completedBookings = bookingRepository.countByStatus(Booking.BookingStatus.COMPLETED);
    long cancelledBookings = bookingRepository.countByStatus(Booking.BookingStatus.CANCELLED);
    
    long totalCars = carRepository.count();
    long availableCars = carRepository.countByAvailableTrue();
    long unavailableCars = totalCars - availableCars;
    

    Double totalRevenue = bookingRepository.sumPaidRevenue();
    
    stats.put("users", Map.of(
        "total", totalUsers,
        "admins", adminUsers,
        "customers", regularUsers
    ));
    
    stats.put("bookings", Map.of(
        "total", totalBookings,
        "confirmed", confirmedBookings,
        "active", activeBookings,
        "completed", completedBookings,
        "cancelled", cancelledBookings
    ));
    
    stats.put("cars", Map.of(
        "total", totalCars,
        "available", availableCars,
        "unavailable", unavailableCars
    ));
    
    stats.put("revenue", totalRevenue != null ? totalRevenue : 0.0);
    stats.put("timestamp", LocalDateTime.now());
    
    return ResponseEntity.ok(stats);
}

}