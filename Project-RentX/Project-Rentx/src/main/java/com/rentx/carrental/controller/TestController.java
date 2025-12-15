package com.rentx.carrental.controller;

import com.rentx.carrental.repository.CarRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/test")
@RequiredArgsConstructor
public class TestController {
    
    private final CarRepository carRepository;
    
    @GetMapping("/database")
    public Map<String, Object> testDatabase() {
        Map<String, Object> response = new HashMap<>();
        try {
            long carCount = carRepository.count();
            response.put("status", "success");
            response.put("message", "Database connection successful");
            response.put("totalCars", carCount);
            response.put("cars", carRepository.findAll());
        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", "Database connection failed: " + e.getMessage());
        }
        return response;
    }
}