package com.rentx.carrental.repository;

import com.rentx.carrental.entity.AdminRequest;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface AdminRequestRepository extends JpaRepository<AdminRequest, Long> {
    List<AdminRequest> findByStatusOrderByRequestedAtDesc(AdminRequest.RequestStatus status);
    Optional<AdminRequest> findByUserIdAndStatus(Long userId, AdminRequest.RequestStatus status);
    boolean existsByUserIdAndStatus(Long userId, AdminRequest.RequestStatus status);
	List<AdminRequest> findByUserId(Long userId);
	List<AdminRequest> findByUserUsername(String username);
	
	
	
	
	
	
	
}