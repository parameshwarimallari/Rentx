package com.rentx.carrental.service;

import com.rentx.carrental.config.AppConfig;
import com.rentx.carrental.entity.Booking;
import com.rentx.carrental.entity.User;
import com.rentx.carrental.repository.BookingRepository;
import com.rentx.carrental.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class LoyaltyService {

	private final BookingRepository bookingRepository;
	private final UserRepository userRepository;
	private final AppConfig appConfig;

	@Transactional(readOnly = true)
	public double calculateDiscount(User user, double totalAmount) {
		if (user == null) {
			log.warn(" User is null in calculateDiscount");
			return 0.0;
		}

		try {
			User fullUser = userRepository.findById(user.getId())
					.orElseThrow(() -> new RuntimeException("User not found in database"));

			log.info("Loyalty Debug - User ID: {}, Username: {}", fullUser.getId(), fullUser.getUsername());

			long completedBookings = bookingRepository.countByUserAndStatus(fullUser, Booking.BookingStatus.COMPLETED);

			long confirmedBookings = bookingRepository.countByUserAndStatus(fullUser, Booking.BookingStatus.CONFIRMED);

			long totalBookingsForDiscount = completedBookings + confirmedBookings;
			log.info("Total bookings for discount calculation: {}", totalBookingsForDiscount);

			double discount = 0.0;
			for (AppConfig.Loyalty.LoyaltyTier tier : appConfig.getLoyalty().getTiers()) {
				if (totalBookingsForDiscount >= tier.getBookings()) {
					discount = totalAmount * tier.getDiscount();
					log.info("Applying {} discount: {}%", tier.getName(), tier.getDiscount() * 100);
					break;
				}
			}

			log.info("Discount calculated: ${} ({}%)", discount, (discount / totalAmount) * 100);
			return discount;

		} catch (Exception e) {
			log.error("Error in calculateDiscount: {}", e.getMessage());
			e.printStackTrace();
			return 0.0;
		}
	}

	@Transactional(readOnly = true)
	public String getLoyaltyTier(User user) {
		if (user == null)
			return "NEW";

		try {
			long completedBookings = bookingRepository.countByUserAndStatus(user, Booking.BookingStatus.COMPLETED);

			long confirmedBookings = bookingRepository.countByUserAndStatus(user, Booking.BookingStatus.CONFIRMED);

			long totalBookings = completedBookings + confirmedBookings;

			String tierName = "NEW";
			for (AppConfig.Loyalty.LoyaltyTier tier : appConfig.getLoyalty().getTiers()) {
				if (totalBookings >= tier.getBookings()) {
					tierName = tier.getName();
				}
			}
			return tierName;

		} catch (Exception e) {
			return "NEW";
		}
	}

	@Transactional(readOnly = true)
	public long getCompletedBookingsCount(User user) {
		if (user == null)
			return 0;

		try {
			long completedBookings = bookingRepository.countByUserAndStatus(user, Booking.BookingStatus.COMPLETED);

			long confirmedBookings = bookingRepository.countByUserAndStatus(user, Booking.BookingStatus.CONFIRMED);

			return completedBookings + confirmedBookings;

		} catch (Exception e) {
			return 0;
		}
	}
}