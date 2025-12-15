package com.rentx.carrental.service;

import com.rentx.carrental.entity.AdminRequest;
import com.rentx.carrental.entity.User;
import com.rentx.carrental.repository.AdminRequestRepository;
import com.rentx.carrental.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional
public class AdminRequestService {
	private final AdminRequestRepository adminRequestRepository;
	private final UserRepository userRepository;
	private final EmailService emailService;

	public AdminRequest requestAdminRole(String message) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		String username = authentication.getName();

		User user = userRepository.findByUsername(username).orElseThrow(() -> new RuntimeException("User not found"));

		if (user.getRole() == User.UserRole.ADMIN) {
			throw new RuntimeException("You are already an admin");
		}

		if (adminRequestRepository.existsByUserIdAndStatus(user.getId(), AdminRequest.RequestStatus.PENDING)) {
			throw new RuntimeException("You already have a pending admin request");
		}

		if (message == null || message.trim().isEmpty()) {
			throw new RuntimeException("Message cannot be empty");
		}

		AdminRequest request = new AdminRequest();
		request.setUser(user);
		request.setMessage(message.trim()); // ✅ Trim whitespace
		request.setStatus(AdminRequest.RequestStatus.PENDING);

		return adminRequestRepository.save(request);
	}

	@Transactional
	public List<AdminRequest> getPendingRequests() {
		return adminRequestRepository.findByStatusOrderByRequestedAtDesc(AdminRequest.RequestStatus.PENDING);
	}

	public AdminRequest processAdminRequest(Long requestId, String action, String notes) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		String username = authentication.getName();

		User adminUser = userRepository.findByUsername(username)
				.orElseThrow(() -> new RuntimeException("Admin user not found"));

		if (adminUser.getRole() != User.UserRole.ADMIN) {
			throw new RuntimeException("Only admins can process admin requests");
		}

		AdminRequest request = adminRequestRepository.findById(requestId)
				.orElseThrow(() -> new RuntimeException("Admin request not found"));

		if (action.equalsIgnoreCase("APPROVE")) {
			User user = request.getUser();
			user.setRole(User.UserRole.ADMIN);
			userRepository.save(user);

			request.setStatus(AdminRequest.RequestStatus.APPROVED);

			try {
				emailService.sendAdminApprovalEmail(user);
			} catch (Exception e) {
				System.err.println("Failed to send approval email: " + e.getMessage());
			}

		} else if (action.equalsIgnoreCase("REJECT")) {
			request.setStatus(AdminRequest.RequestStatus.REJECTED);
		} else {
			throw new RuntimeException("Invalid action. Use 'APPROVE' or 'REJECT'");
		}

		request.setProcessedAt(LocalDateTime.now());
		request.setProcessedBy(adminUser);
		request.setAdminNotes(notes);

		return adminRequestRepository.save(request);
	}
}