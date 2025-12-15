package com.rentx.carrental.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.rentx.carrental.dto.UpdateProfileRequest;
import com.rentx.carrental.dto.UserDTO;
import com.rentx.carrental.entity.AdminRequest;
import com.rentx.carrental.entity.User;
import com.rentx.carrental.repository.AdminRequestRepository;
import com.rentx.carrental.repository.UserRepository;
import com.rentx.carrental.service.AdminRequestService;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:5173")
public class UserController {

	private final AdminRequestService adminRequestService;
	private final UserRepository userRepository;
	private final AdminRequestRepository adminRequestRepository;

	@PostMapping("/request-admin")
	public ResponseEntity<?> requestAdminRole(@RequestBody Map<String, String> request) {
		try {
			String message = request.get("message");
			adminRequestService.requestAdminRole(message);
			return ResponseEntity.ok("Admin request submitted successfully");
		} catch (Exception e) {
			return ResponseEntity.badRequest().body(e.getMessage());
		}
	}

	@GetMapping("/my-admin-requests")
	public ResponseEntity<?> getMyAdminRequests() {
		try {
			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			String username = authentication.getName();

			User user = userRepository.findByUsername(username)
					.orElseThrow(() -> new RuntimeException("User not found"));

			List<AdminRequest> userRequests = adminRequestRepository.findByUserId(user.getId());

			return ResponseEntity.ok(userRequests);

		} catch (Exception e) {
			return ResponseEntity.badRequest().body("Error fetching admin requests: " + e.getMessage());
		}
	}

	@PutMapping("/profile")
	public ResponseEntity<UserDTO> updateProfile(@RequestBody UpdateProfileRequest request) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		String username = authentication.getName();

		User user = userRepository.findByUsername(username).orElseThrow(() -> new RuntimeException("User not found"));

		user.setFirstName(request.getFirstName());
		user.setLastName(request.getLastName());
		user.setPhoneNumber(request.getPhoneNumber());
		user.setDriverLicense(request.getDriverLicense());

		User updatedUser = userRepository.save(user);

		return ResponseEntity.ok(new UserDTO(updatedUser));
	}

	@GetMapping("/profile")
	public ResponseEntity<?> getCurrentUserProfile() {
		try {
			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			String username = authentication.getName();

			User user = userRepository.findByUsername(username)
					.orElseThrow(() -> new RuntimeException("User not found"));

			Map<String, Object> userProfile = new HashMap<>();
			userProfile.put("id", user.getId());
			userProfile.put("username", user.getUsername());
			userProfile.put("email", user.getEmail());
			userProfile.put("firstName", user.getFirstName());
			userProfile.put("lastName", user.getLastName());
			userProfile.put("phoneNumber", user.getPhoneNumber());
			userProfile.put("driverLicense", user.getDriverLicense());
			userProfile.put("role", user.getRole());
			userProfile.put("createdAt", user.getCreatedAt());
			userProfile.put("updatedAt", user.getUpdatedAt());

			return ResponseEntity.ok(userProfile);

		} catch (Exception e) {
			return ResponseEntity.badRequest().body("Error fetching profile: " + e.getMessage());
		}
	}
}