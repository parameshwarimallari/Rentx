package com.rentx.carrental.controller;


import com.rentx.carrental.service.DatabaseHealthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/health")
@RequiredArgsConstructor
public class HealthController {
    
    private final DatabaseHealthService databaseHealthService;
    
    @GetMapping
    public ResponseEntity<Map<String, Object>> healthCheck() {
        Map<String, Object> health = new HashMap<>();
        health.put("status", "UP");
        health.put("database", databaseHealthService.isDatabaseConnected() ? "CONNECTED" : "DISCONNECTED");
        health.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.ok(health);
    }
}