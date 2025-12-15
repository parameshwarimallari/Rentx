package com.rentx.carrental.controller;

import com.rentx.carrental.entity.Booking;
import com.rentx.carrental.entity.Car;
import com.rentx.carrental.exception.CarNotFoundException;
import com.rentx.carrental.repository.BookingRepository;
import com.rentx.carrental.repository.CarRepository;
import com.rentx.carrental.service.CarService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/cars")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:5173")
public class CarController {

	private final CarService carService;
	private final CarRepository carRepository;
	private final BookingRepository bookingRepository;

	@GetMapping
	public ResponseEntity<List<Car>> getAllCars() {
		return ResponseEntity.ok(carService.getAllAvailableCars());
	}

	@PostMapping
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<Car> addCar(@Valid @RequestBody Car car) {
		car.setActive(true);
		car.setAvailable(true);
		Car savedCar = carRepository.save(car);
		return ResponseEntity.status(HttpStatus.CREATED).body(savedCar);
	}

	@PutMapping("/{id}")
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<Car> updateCar(@PathVariable Long id, @Valid @RequestBody Car carDetails) {
		Car car = carRepository.findById(id).orElseThrow(() -> new CarNotFoundException(id));

		car.setBrand(carDetails.getBrand());
		car.setModel(carDetails.getModel());
		car.setYear(carDetails.getYear());
		car.setColor(carDetails.getColor());
		car.setDailyRate(carDetails.getDailyRate());
		car.setLicensePlate(carDetails.getLicensePlate());
		car.setCategory(carDetails.getCategory());
		car.setImagePath(carDetails.getImagePath());

		Car updatedCar = carRepository.save(car);
		return ResponseEntity.ok(updatedCar);
	}

	@PutMapping("/{id}/toggle")
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<Car> toggleAvailability(@PathVariable Long id) {
		Car car = carRepository.findById(id).orElseThrow(() -> new CarNotFoundException(id));

		car.setAvailable(!car.getAvailable());
		Car updatedCar = carRepository.save(car);

		carService.clearCarCaches();

		return ResponseEntity.ok(updatedCar);
	}

	@DeleteMapping("/{id}")
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<?> deleteCar(@PathVariable Long id) {
		Car car = carRepository.findById(id).orElseThrow(() -> new CarNotFoundException(id));

		List<Booking> activeBookings = bookingRepository.findByCarCarIdAndStatusIn(id,
				Arrays.asList(Booking.BookingStatus.CONFIRMED, Booking.BookingStatus.ACTIVE));

		if (!activeBookings.isEmpty()) {
			return ResponseEntity.badRequest().body("Cannot delete car with active bookings");
		}

		carRepository.delete(car);

		carService.clearCarCaches();

		return ResponseEntity.ok().build();
	}

	@GetMapping("/search")
	public ResponseEntity<?> searchCars(@RequestParam(required = false) String brand,
			@RequestParam(required = false) String category, @RequestParam(required = false) Double maxPrice,
			@RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime startDate,
			@RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime endDate) {
		try {
			List<Car> cars = carService.searchCars(brand, category, maxPrice, startDate, endDate);
			return ResponseEntity.ok(cars);
		} catch (RuntimeException e) {
			return ResponseEntity.badRequest().body(e.getMessage());
		}
	}

	@GetMapping("/{id}")
	public ResponseEntity<Car> getCarById(@PathVariable Long id) {
		return ResponseEntity.ok(carService.getCarById(id));
	}

	@GetMapping("/{id}/availability")
	public ResponseEntity<Map<String, Object>> getCarAvailability(@PathVariable Long id,
			@RequestParam(required = false) Integer year, @RequestParam(required = false) Integer month) {

		Car car = carRepository.findById(id).orElseThrow(() -> new CarNotFoundException(id));

		LocalDateTime now = LocalDateTime.now();
		int targetYear = year != null ? year : now.getYear();
		int targetMonth = month != null ? month : now.getMonthValue();

		LocalDateTime startOfMonth = LocalDateTime.of(targetYear, targetMonth, 1, 0, 0);
		LocalDateTime endOfMonth = startOfMonth.plusMonths(1).minusSeconds(1);

		List<Booking> bookings = bookingRepository.findByCarCarIdAndDatesBetween(id, startOfMonth, endOfMonth);

		Set<LocalDate> bookedDates = bookings.stream().flatMap(booking -> {
			LocalDate start = booking.getStartDate().toLocalDate();
			LocalDate end = booking.getEndDate().toLocalDate();
			return start.datesUntil(end.plusDays(1));
		}).collect(Collectors.toSet());

		Map<String, Object> response = new HashMap<>();
		response.put("carId", id);
		response.put("year", targetYear);
		response.put("month", targetMonth);
		response.put("bookedDates", bookedDates.stream().map(LocalDate::toString).collect(Collectors.toList()));
		response.put("totalBookings", bookings.size());

		return ResponseEntity.ok(response);
	}
}