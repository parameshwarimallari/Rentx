
package com.rentx.carrental.service;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import org.hibernate.validator.internal.util.stereotypes.Lazy;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.rentx.carrental.dto.BookingRequest;
import com.rentx.carrental.dto.BookingResponse;
import com.rentx.carrental.entity.Booking;
import com.rentx.carrental.entity.Booking.BookingStatus;
import com.rentx.carrental.entity.Booking.PickupStatus;
import com.rentx.carrental.entity.Booking.RefundStatus;
import com.rentx.carrental.entity.Car;
import com.rentx.carrental.entity.User;
import com.rentx.carrental.exception.BookingAlreadyCancelledException;
import com.rentx.carrental.exception.BookingAlreadyStartedException;
import com.rentx.carrental.exception.BookingCompletedException;
import com.rentx.carrental.exception.BookingConflictException;
import com.rentx.carrental.exception.CarNotFoundException;
import com.rentx.carrental.exception.InvalidCancellationException;
import com.rentx.carrental.repository.BookingRepository;
import com.rentx.carrental.repository.CarRepository;
import com.rentx.carrental.repository.UserRepository;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
@Transactional
public class BookingService {
    private final EmailService emailService;
    private final BookingRepository bookingRepository;
    private final CarRepository carRepository;
    private final UserRepository userRepository;
    @Lazy
    private final LoyaltyService loyaltyService;
    @Lazy
    private final PaymentService paymentService;
   
  
    @Transactional
    public BookingResponse createBooking(BookingRequest request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        Car car = carRepository.findById(request.getCarId())
                .orElseThrow(() -> new CarNotFoundException(request.getCarId()));
        
        List<Booking> existingBookings = bookingRepository.findConflictingBookings(request.getCarId(),
                request.getStartDate(), request.getEndDate());

        if (!existingBookings.isEmpty()) {
            throw new BookingConflictException("Car is already booked for the selected dates");
        }

        long hours = ChronoUnit.HOURS.between(request.getStartDate(), request.getEndDate());
        double days = Math.ceil(hours / 24.0);
        days = Math.max(1, days);
        double totalPrice = car.getDailyRate() * days;

        double discount = loyaltyService.calculateDiscount(user, totalPrice);
        double finalPrice = totalPrice - discount;

        
        Booking booking = new Booking();
        booking.setPaymentMethodSelected("payNow".equals(request.getPaymentOption()) ? "PAY_NOW" : "PAY_AT_PICKUP");
        booking.setUser(user);
        booking.setCar(car);
        booking.setStartDate(request.getStartDate());
        booking.setEndDate(request.getEndDate());
        booking.setTotalPrice(finalPrice);
        booking.setDiscountAmount(discount);
        booking.setStatus(Booking.BookingStatus.CONFIRMED);
        
        if ("payNow".equals(request.getPaymentOption())) {
            booking.setPaymentStatus("PENDING");
        } else if ("payLater".equals(request.getPaymentOption())) {
            booking.setPaymentStatus("PAY_AT_PICKUP");
        }

        Booking savedBooking = bookingRepository.save(booking);
        
        try {
            emailService.sendBookingConfirmation(user, savedBooking);
            System.out.println("Booking confirmation email sent to: " + user.getEmail());
        } catch (Exception e) {
            System.err.println("Failed to send email: " + e.getMessage());
        }
        
        return convertToResponse(savedBooking, discount);
    }
    @Transactional(readOnly = true)
    public List<BookingResponse> getUserBookings() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String username = authentication.getName();
            
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new RuntimeException("User not found"));
            
            System.out.println("User: " + user.getUsername() + ", ID: " + user.getId());

            List<Booking> bookings = bookingRepository.findByUserOrderByBookingDateDesc(user);
            System.out.println("Found " + bookings.size() + " bookings");

            return bookings.stream().map(booking -> {
                double originalPrice = calculateOriginalPrice(booking);
                double discount = originalPrice - booking.getTotalPrice();
                return convertToResponse(booking, discount);
            }).collect(Collectors.toList());

        } catch (Exception e) {
            System.err.println("ERROR in getUserBookings: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }


    private double calculateOriginalPrice(Booking booking) {
    	  if (booking == null || booking.getCar() == null || 
    		        booking.getStartDate() == null || booking.getEndDate() == null) {
    		        return 0.0;
    		    }

        try {
        	 long days = ChronoUnit.DAYS.between(booking.getStartDate(), booking.getEndDate());
             double dailyRate = booking.getCar().getDailyRate();
             return dailyRate * Math.max(1, days);
        } catch (Exception e) {
            System.err.println("Error calculating original price: " + e.getMessage());
            return 0.0;
        }
    }

    public BookingResponse getBookingById(Long id) {
        Booking booking = bookingRepository.findById(id).orElseThrow(() -> new RuntimeException("Booking not found"));
        double originalPrice = calculateOriginalPrice(booking);
        double discount = originalPrice - booking.getTotalPrice();
        return convertToResponse(booking, discount);
    }
    @Transactional
    public BookingResponse cancelBooking(Long bookingId, String cancellationReason) {
        Booking booking = bookingRepository.findById(bookingId)
                .orElseThrow(() -> new RuntimeException("Booking not found"));

        if (booking.getStatus() == Booking.BookingStatus.CANCELLED) {
            throw new BookingAlreadyCancelledException(bookingId);
        }
        if (booking.getStatus() == Booking.BookingStatus.COMPLETED) {
            throw new BookingCompletedException(bookingId);
        }

        LocalDateTime now = LocalDateTime.now();
        if (now.isAfter(booking.getStartDate())) {
            throw new BookingAlreadyStartedException(bookingId);
        }

        if (booking.getStatus() != Booking.BookingStatus.CONFIRMED) {
            throw new InvalidCancellationException(bookingId);
        }

        String paymentStatus = booking.getPaymentStatus();
        boolean isPaidOnline = "PAID".equals(paymentStatus);
        boolean isPendingPayment = "PENDING".equals(paymentStatus);
        
        double refundAmount = 0.0;

        if (isPaidOnline) {
            long hoursUntilPickup = ChronoUnit.HOURS.between(now, booking.getStartDate());
            refundAmount = calculateRefundAmount(booking.getTotalPrice(), hoursUntilPickup);
            System.out.println("Online payment - Refund calculated: " + refundAmount);
            
            if (refundAmount > 0) {
                booking.setRefundStatus(RefundStatus.PENDING);
            }
        } else if (isPendingPayment) {
            booking.setPaymentStatus("PAY_AT_PICKUP");
            System.out.println("Pending payment converted to Pay at Pickup upon cancellation");
        } else {
            System.out.println(" Pay at Pickup - No refund applicable");
        }

        booking.setStatus(Booking.BookingStatus.CANCELLED);
        booking.setCancellationReason(cancellationReason);
        booking.setCancellationDate(now);
        booking.setRefundAmount(refundAmount);

        bookingRepository.save(booking);

        System.out.println(" Cancellation Details:");
        System.out.println("   - Payment Method: " + booking.getPaymentStatus());
        System.out.println("   - Original Amount: " + booking.getTotalPrice());
        System.out.println("   - Refund Amount: " + refundAmount);
        System.out.println("   - Final Charge: " + (booking.getTotalPrice() - refundAmount));

        try {
            emailService.sendBookingCancellation(booking.getUser(), booking);
            System.out.println("Cancellation email sent to: " + booking.getUser().getEmail());
        } catch (Exception e) {
            System.err.println("Failed to send cancellation email: " + e.getMessage());
        }

        if (isPaidOnline && refundAmount > 0) {
            processRefund(booking, refundAmount);
        }

        Double discountAmount = booking.getDiscountAmount();
        if (discountAmount == null) {
            discountAmount = 0.0;
        }

        return convertToResponse(booking, discountAmount);
    }

    private void processRefund(Booking booking, double refundAmount) {
        try {
            System.out.println("Processing refund of $" + refundAmount + " for booking " + booking.getId());
            System.out.println("Refund will be processed to original payment method");
        } catch (Exception e) {
            System.err.println("Refund processing failed: " + e.getMessage());
        }
    }

    private double calculateRefundAmount(double totalAmount, long hoursUntilPickup) {
        if (hoursUntilPickup > 48) {
            return totalAmount * 0.8; 
        } else if (hoursUntilPickup > 24) {
            return totalAmount * 0.5; 
        } else {
            return 0.0; 
        }
    }


    @Transactional(readOnly = true)
    public List<BookingResponse> getUserBookingsByFilter(String filter) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User user = (User) authentication.getPrincipal();

        List<Booking> bookings;
        LocalDateTime now = LocalDateTime.now();

        switch (filter.toUpperCase()) {
            case "UPCOMING":
                bookings = bookingRepository.findByUserOrderByBookingDateDesc(user)
                    .stream()
                    .filter(booking -> booking.getStartDate().isAfter(now) && 
                                     (booking.getStatus() == BookingStatus.CONFIRMED || 
                                      booking.getStatus() == BookingStatus.PENDING))
                    .collect(Collectors.toList());
                break;
            case "ACTIVE":
                bookings = bookingRepository.findByUserAndStatusOrderByBookingDateDesc(user, BookingStatus.ACTIVE);
                break;
            case "COMPLETED":
                bookings = bookingRepository.findByUserAndStatusOrderByBookingDateDesc(user, BookingStatus.COMPLETED);
                break;
            case "CANCELLED":
                bookings = bookingRepository.findByUserAndStatusOrderByBookingDateDesc(user, BookingStatus.CANCELLED);
                break;
            case "ALL":
            default:
                bookings = bookingRepository.findByUserOrderByBookingDateDesc(user);
                break;
        }

        return bookings.stream().map(booking -> {
            double originalPrice = calculateOriginalPrice(booking);
            double discount = originalPrice - booking.getTotalPrice();
            return convertToResponse(booking, discount);
        }).collect(Collectors.toList());
    }
    @Transactional
    @Scheduled(fixedRate = 300000) 
    public void updateBookingStatuses() {
        LocalDateTime now = LocalDateTime.now();

        List<Booking> toActivate = bookingRepository.findByStartDateBeforeAndStatus(now, Booking.BookingStatus.CONFIRMED);
        for (Booking booking : toActivate) {
            booking.setStatus(Booking.BookingStatus.ACTIVE);
            bookingRepository.save(booking);
            System.out.println("Booking " + booking.getId() + " set to ACTIVE");
        }

        List<Booking> toComplete = bookingRepository.findByEndDateBeforeAndStatus(now, Booking.BookingStatus.ACTIVE);
        for (Booking booking : toComplete) {
            booking.setStatus(Booking.BookingStatus.COMPLETED);
            bookingRepository.save(booking);
            System.out.println("Booking " + booking.getId() + " set to COMPLETED");
        }
    }

	

	
    @Transactional
    public BookingResponse markAsPickedUp(Long bookingId, String pickupNotes) {
        try {
            Booking booking = bookingRepository.findById(bookingId)
                .orElseThrow(() -> new RuntimeException("Booking not found"));

            if (booking.getStatus() != BookingStatus.CONFIRMED) {
                throw new RuntimeException("Booking must be in CONFIRMED status to be picked up");
            }

            booking.setStatus(BookingStatus.ACTIVE);
            booking.setPickupStatus(PickupStatus.PICKED_UP);
            booking.setActualPickupTime(LocalDateTime.now());
            booking.setPickupNotes(pickupNotes);

            Booking savedBooking = bookingRepository.save(booking);

            try {
                emailService.sendPickupConfirmation(booking.getUser(), savedBooking);
                System.out.println("Pickup confirmation email sent to: " + booking.getUser().getEmail());
            } catch (Exception e) {
                System.err.println("Failed to send pickup email: " + e.getMessage());
            }

            return convertToResponse(savedBooking, savedBooking.getDiscountAmount() != null ? savedBooking.getDiscountAmount() : 0.0);
            
        } catch (Exception e) {
            System.err.println("Error marking booking as picked up: " + e.getMessage());
            throw new RuntimeException("Failed to mark booking as picked up: " + e.getMessage());
        }
    }
    @Transactional
    public BookingResponse markAsReturned(Long bookingId, Double extraCharges, String returnNotes) {
        try {
            Booking booking = bookingRepository.findById(bookingId)
                .orElseThrow(() -> new RuntimeException("Booking not found"));

            if (booking.getStatus() != BookingStatus.ACTIVE) {
                throw new RuntimeException("Booking must be in ACTIVE status to be returned");
            }

            LocalDateTime actualReturnTime = LocalDateTime.now();
            booking.setActualReturnTime(actualReturnTime);
            
            double latePenalty = 0.0;
            boolean isLate = false;
            
            if (actualReturnTime.isAfter(booking.getEndDate())) {
                isLate = true;
                long lateHours = ChronoUnit.HOURS.between(booking.getEndDate(), actualReturnTime);
                
              
                if (lateHours <= 2) {
                    latePenalty = 0.0; 
                } else if (lateHours <= 6) {
                    latePenalty = booking.getCar().getDailyRate() * 0.25;
                } else if (lateHours <= 24) {
                    latePenalty = booking.getCar().getDailyRate() * 0.5;
                } else {
                    long extraDays = (lateHours + 23) / 24; 
                    latePenalty = booking.getCar().getDailyRate() * 1.5 * extraDays;
                }
                
                booking.setLateReturnPenalty(latePenalty);
                booking.setIsLateReturn(true);
                
                System.out.println("Late return detected: " + lateHours + 
                                 " hours late - Penalty: ₹" + latePenalty);
            }
            
            double additionalCharges = (extraCharges != null ? extraCharges : 0.0);
            
            double finalAmount = booking.getTotalPrice() + latePenalty + additionalCharges;
            booking.setTotalPrice(finalAmount);
            booking.setExtraCharges(additionalCharges);
            booking.setStatus(BookingStatus.COMPLETED);
            booking.setPickupStatus(PickupStatus.RETURNED);

            Booking savedBooking = bookingRepository.save(booking);

            try {
                emailService.sendReturnConfirmation(booking.getUser(), savedBooking);
                System.out.println("Return confirmation email sent to: " + booking.getUser().getEmail());
            } catch (Exception e) {
                System.err.println("Failed to send return email: " + e.getMessage());
            }

            return convertToResponse(savedBooking, 
                savedBooking.getDiscountAmount() != null ? savedBooking.getDiscountAmount() : 0.0);
            
        } catch (Exception e) {
            System.err.println("Error marking booking as returned: " + e.getMessage());
            throw new RuntimeException("Failed to mark booking as returned: " + e.getMessage());
        }
    }
    @Transactional(readOnly = true)
    public List<BookingResponse> getActiveBookings() {
        try {
            LocalDateTime now = LocalDateTime.now();
            
            List<Booking> activeBookings = bookingRepository.findByStatus(BookingStatus.ACTIVE);
            
            List<Booking> confirmedBookings = bookingRepository.findByStartDateBeforeAndStatus(now, BookingStatus.CONFIRMED);
            
            List<Booking> allActiveBookings = new ArrayList<>();
            allActiveBookings.addAll(activeBookings);
            allActiveBookings.addAll(confirmedBookings);
            
            return allActiveBookings.stream()
                .map(booking -> {
                    double originalPrice = calculateOriginalPrice(booking);
                    double discount = originalPrice - booking.getTotalPrice();
                    return convertToResponse(booking, discount);
                })
                .collect(Collectors.toList());
                
        } catch (Exception e) {
            System.err.println("Error fetching active bookings: " + e.getMessage());
            throw new RuntimeException("Failed to fetch active bookings: " + e.getMessage());
        }
    }
    
    @Transactional
    public BookingResponse markAsReturned(Long bookingId, String returnNotes) {
        try {
            Booking booking = bookingRepository.findById(bookingId)
                .orElseThrow(() -> new RuntimeException("Booking not found"));

            if (booking.getStatus() != BookingStatus.ACTIVE) {
                throw new RuntimeException("Booking must be in ACTIVE status to be returned");
            }

            LocalDateTime actualReturnTime = LocalDateTime.now();
            booking.setActualReturnTime(actualReturnTime);
            booking.setStatus(BookingStatus.COMPLETED);
            booking.setPickupStatus(PickupStatus.RETURNED);
            
            double latePenalty = 0.0;
            boolean isLate = false;
            
            if (actualReturnTime.isAfter(booking.getEndDate())) {
                isLate = true;
                latePenalty = calculateLateReturnPenalty(booking, actualReturnTime);
                booking.setLateReturnPenalty(latePenalty);
                booking.setIsLateReturn(true);
                
                System.out.println("Late return detected: " + 
                    booking.getLateHours() + " hours late - Penalty: ₹" + latePenalty);
            }
            
            double finalAmount = booking.getTotalPrice() + latePenalty;
            booking.setTotalPrice(finalAmount);

            Booking savedBooking = bookingRepository.save(booking);

            try {
                emailService.sendReturnConfirmation(booking.getUser(), savedBooking);
                System.out.println("Return confirmation email sent to: " + booking.getUser().getEmail());
            } catch (Exception e) {
                System.err.println("Failed to send return email: " + e.getMessage());
            }

            return convertToResponse(savedBooking, savedBooking.getDiscountAmount() != null ? savedBooking.getDiscountAmount() : 0.0);
            
        } catch (Exception e) {
            System.err.println("Error marking booking as returned: " + e.getMessage());
            throw new RuntimeException("Failed to mark booking as returned: " + e.getMessage());
        }
    }
    
    private double calculateLateReturnPenalty(Booking booking, LocalDateTime actualReturnTime) {
        long lateHours = ChronoUnit.HOURS.between(booking.getEndDate(), actualReturnTime);
        double dailyRate = booking.getCar().getDailyRate();
        
     
        
        if (lateHours <= 2) {
            return 0.0; 
        } else if (lateHours <= 24) {
            return dailyRate * 0.5; 
        } else {
            long extraDays = (lateHours + 23) / 24; 
            return dailyRate * 1.5 * extraDays; 
        }
    }
    
    @Transactional(readOnly = true)
    public List<BookingResponse> getOverdueBookings() {
        LocalDateTime now = LocalDateTime.now();
        
        List<Booking> activeBookings = bookingRepository.findByStatus(BookingStatus.ACTIVE);
        
        return activeBookings.stream()
            .filter(booking -> now.isAfter(booking.getEndDate())) 
            .map(booking -> {
                double originalPrice = calculateOriginalPrice(booking);
                double discount = originalPrice - booking.getTotalPrice();
                return convertToResponse(booking, discount);
            })
            .collect(Collectors.toList());
    }
    
    public BookingResponse convertToResponse(Booking booking, double discount) {
    	 long hours = ChronoUnit.HOURS.between(booking.getStartDate(), booking.getEndDate());
    	    double days = Math.ceil(hours / 24.0);
    	    days = Math.max(1, days);
    	    int totalDays = (int) days;
    	    return BookingResponse.builder()
    	            .id(booking.getId())
    	            .carId(booking.getCar().getCarId())
    	            .carBrand(booking.getCar().getBrand())
    	            .carModel(booking.getCar().getModel())
    	            .carImage(booking.getCar().getImagePath())
    	            .startDate(booking.getStartDate())
    	            .endDate(booking.getEndDate())
    	            .totalPrice(booking.getTotalPrice())
    	            .bookingDate(booking.getBookingDate())
    	            .status(booking.getStatus().name())
    	            .totalDays(totalDays)
    	            .discountAmount(discount)
    	            .refundAmount(booking.getRefundAmount())
    	            .cancellationReason(booking.getCancellationReason())
    	            .cancellationDate(booking.getCancellationDate())
    	            .paymentStatus(booking.getPaymentStatus())
    	            .refundStatus(booking.getRefundStatus() != null ? booking.getRefundStatus().name() : "NONE")
    	            .lateReturnPenalty(booking.getLateReturnPenalty() != null ? booking.getLateReturnPenalty() : 0.0)
    	            .isLateReturn(booking.getIsLateReturn() != null ? booking.getIsLateReturn() : false)
    	            .actualReturnTime(booking.getActualReturnTime())
    	            .extraCharges(booking.getExtraCharges() != null ? booking.getExtraCharges() : 0.0)
    	            .build();
    }
    @Transactional
    public BookingResponse extendBooking(Long bookingId, LocalDateTime newEndDate) {
        try {
            System.out.println("🔄 Extending booking " + bookingId + " to " + newEndDate);
            
            Booking booking = bookingRepository.findById(bookingId)
                    .orElseThrow(() -> new RuntimeException("Booking not found"));
            
            if (booking.getStatus() != BookingStatus.ACTIVE) {
                throw new RuntimeException("Can only extend active bookings");
            }
            
            if (!newEndDate.isAfter(booking.getEndDate())) {
                throw new RuntimeException("New end date must be after current end date");
            }
            
            List<Booking> conflictingBookings = bookingRepository.findConflictingBookings(
                    booking.getCar().getCarId(),
                    booking.getEndDate(), 
                    newEndDate
            );
            
            conflictingBookings = conflictingBookings.stream()
                    .filter(b -> !b.getId().equals(bookingId))
                    .collect(Collectors.toList());
            
            if (!conflictingBookings.isEmpty()) {
                throw new RuntimeException("Car not available for extended period");
            }
            
            long extraHours = ChronoUnit.HOURS.between(booking.getEndDate(), newEndDate);
            double extraDays = Math.ceil(extraHours / 24.0);
            extraDays = Math.max(1, extraDays);
            double extensionCharge = booking.getCar().getDailyRate() * extraDays;
            
            System.out.println("💰 Extension charge: " + extraDays + " days × ₹" + 
                             booking.getCar().getDailyRate() + " = ₹" + extensionCharge);
            
            double originalPrice = booking.getTotalPrice();
            LocalDateTime originalEndDate = booking.getEndDate();
            
            booking.setEndDate(newEndDate);
            booking.setTotalPrice(originalPrice + extensionCharge);
            
            Booking savedBooking = bookingRepository.save(booking);
            
            try {
                emailService.sendExtensionConfirmation(booking.getUser(), savedBooking, 
                                                     extensionCharge, originalEndDate);
                System.out.println("Extension confirmation email sent");
            } catch (Exception e) {
                System.err.println("Failed to send extension email: " + e.getMessage());
            }
            
            return convertToResponse(savedBooking, 
                    savedBooking.getDiscountAmount() != null ? savedBooking.getDiscountAmount() : 0.0);
            
        } catch (Exception e) {
            System.err.println("Error extending booking: " + e.getMessage());
            throw new RuntimeException("Failed to extend booking: " + e.getMessage());
        }
    }
	
}
