package com.rentx.carrental.service;

import java.time.LocalDateTime;
import java.util.List;
import org.springframework.stereotype.Service;
import com.rentx.carrental.entity.Booking;
import com.rentx.carrental.entity.User;
import com.rentx.carrental.repository.BookingRepository;
import com.rentx.carrental.repository.UserRepository;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AdminService {
    private final BookingRepository bookingRepository;
    private final UserRepository userRepository;

    public List<Booking> getAllBookings() {
        return bookingRepository.findAll();
    }

    public Booking markBookingAsCompleted(Long bookingId, String notes) {
        Booking booking = bookingRepository.findById(bookingId)
                .orElseThrow(() -> new RuntimeException("Booking not found"));
        
        booking.setStatus(Booking.BookingStatus.COMPLETED);
        if (notes != null) {
            booking.setPickupNotes(notes);
        }
        booking.setActualReturnTime(LocalDateTime.now());
        
        return bookingRepository.save(booking);
    }

    public Booking updateBookingStatus(Long bookingId, String status) {
        Booking booking = bookingRepository.findById(bookingId)
                .orElseThrow(() -> new RuntimeException("Booking not found"));
        
        booking.setStatus(Booking.BookingStatus.valueOf(status));
        return bookingRepository.save(booking);
    }

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }
}