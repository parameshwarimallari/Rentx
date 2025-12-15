package com.rentx.carrental.service;

import com.rentx.carrental.entity.Car;
import com.rentx.carrental.exception.CarNotFoundException;
import com.rentx.carrental.repository.CarRepository;
import com.rentx.carrental.util.HtmlEscapeUtil;
import com.rentx.carrental.util.SqlInjectionProtectionUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class CarService {

	private final CarRepository carRepository;

	@Cacheable(value = "availableCars", unless = "#result == null || #result.isEmpty()")
	public List<Car> getAllAvailableCars() {
		log.info("Fetching available cars from database");
		return carRepository.findAvailableActiveCars();
	}

	@Cacheable(value = "carDetails", key = "#id", unless = "#result == null")
	public Car getCarById(Long id) {
		log.info("Fetching car details from database for ID: {}", id);
		return carRepository.findById(id).orElseThrow(() -> new CarNotFoundException(id));
	}

	@Cacheable(value = "cars", key = "{#brand, #category, #maxPrice}", unless = "#result == null || #result.isEmpty()")
	public List<Car> searchCars(String brand, String category, Double maxPrice) {
		log.info("Searching cars with filters - Brand: {}, Category: {}, MaxPrice: {}", brand, category, maxPrice);

		String safeBrand = brand != null ? sanitizeInput(brand) : null;
		String safeCategory = category != null ? sanitizeInput(category) : null;

		if (safeBrand != null && SqlInjectionProtectionUtil.containsSqlInjection(safeBrand)) {
			log.warn("Potential SQL injection detected in brand parameter: {}", safeBrand);
			throw new IllegalArgumentException("Invalid search parameter");
		}

		if (safeCategory != null && SqlInjectionProtectionUtil.containsSqlInjection(safeCategory)) {
			log.warn("Potential SQL injection detected in category parameter: {}", safeCategory);
			throw new IllegalArgumentException("Invalid search parameter");
		}

		if (safeBrand != null && safeCategory != null && maxPrice != null) {
			Car.CarCategory catEnum = Car.CarCategory.valueOf(safeCategory.toUpperCase());
			return carRepository.findByBrandAndCategoryAndDailyRateLessThanEqual(safeBrand, catEnum, maxPrice);
		} else if (safeBrand != null && safeCategory != null) {
			Car.CarCategory catEnum = Car.CarCategory.valueOf(safeCategory.toUpperCase());
			return carRepository.findByBrandAndCategory(safeBrand, catEnum);
		} else if (safeBrand != null) {
			return carRepository.findByBrand(safeBrand);
		} else if (safeCategory != null) {
			Car.CarCategory catEnum = Car.CarCategory.valueOf(safeCategory.toUpperCase());
			return carRepository.findByCategory(catEnum);
		} else if (maxPrice != null) {
			return carRepository.findByDailyRateLessThanEqual(maxPrice);
		} else {
			return getAllAvailableCars();
		}
	}

	@CacheEvict(value = { "availableCars", "cars", "carDetails" }, allEntries = true)
	public Car updateCar(Car car) {
		log.info("Updating car and evicting cache for car ID: {}", car.getCarId());
		return carRepository.save(car);
	}

	@CacheEvict(value = { "availableCars", "cars", "carDetails" }, allEntries = true)
	public void deleteCar(Long carId) {
		log.info("Deleting car and evicting cache for car ID: {}", carId);
		carRepository.deleteById(carId);
	}

	@Scheduled(fixedRate = 3600000)
	@CacheEvict(value = { "availableCars", "cars", "carDetails" }, allEntries = true)
	public void clearCarCaches() {
		log.info("Scheduled cache eviction for car data at {}", LocalDateTime.now());
	}

	public List<Car> getCarsByCategory(String category) {
		String safeCategory = sanitizeInput(category);
		if (safeCategory != null && SqlInjectionProtectionUtil.containsSqlInjection(safeCategory)) {
			throw new IllegalArgumentException("Invalid category parameter");
		}

		Car.CarCategory catEnum = Car.CarCategory.valueOf(safeCategory.toUpperCase());
		return carRepository.findByCategory(catEnum);
	}

	@Cacheable(value = "cars", key = "{#brand, #category, #maxPrice, #startDate, #endDate}", unless = "#result == null || #result.isEmpty()")
	public List<Car> searchCars(String brand, String category, Double maxPrice, LocalDateTime startDate,
			LocalDateTime endDate) {

		log.info("Searching cars with date filters - Brand: {}, Category: {}, MaxPrice: {}, Start: {}, End: {}", brand,
				category, maxPrice, startDate, endDate);

		String safeBrand = brand != null ? sanitizeInput(brand) : null;
		String safeCategory = category != null ? sanitizeInput(category) : null;

		if (safeBrand != null && SqlInjectionProtectionUtil.containsSqlInjection(safeBrand)) {
			throw new IllegalArgumentException("Invalid brand parameter");
		}

		if (safeCategory != null && SqlInjectionProtectionUtil.containsSqlInjection(safeCategory)) {
			throw new IllegalArgumentException("Invalid category parameter");
		}

		List<Car> cars;

		if (startDate != null && endDate != null) {
			cars = carRepository.findAvailableCarsBetweenDates(startDate, endDate);
		} else {
			cars = carRepository.findAvailableActiveCars();
		}

		return cars.stream().filter(car -> safeBrand == null || car.getBrand().equalsIgnoreCase(safeBrand))
				.filter(car -> safeCategory == null || car.getCategory().name().equalsIgnoreCase(safeCategory))
				.filter(car -> maxPrice == null || car.getDailyRate() <= maxPrice).collect(Collectors.toList());
	}

	private String sanitizeInput(String input) {
		String escaped = HtmlEscapeUtil.escapeHtmlAndLimit(input, 50);
		return SqlInjectionProtectionUtil.sanitizeInput(escaped);
	}
}