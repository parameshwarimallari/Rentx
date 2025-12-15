package com.rentx.carrental.security;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Component
@Order(1)
@Slf4j
public class RateLimitingFilter implements Filter {
    
    @Value("${app.rate-limit.max-requests:5}")
    private int maxRequests;
    
    @Value("${app.rate-limit.time-window:60}")
    private int timeWindowSeconds;
    
    private final ConcurrentHashMap<String, RequestCounter> requestCounts = new ConcurrentHashMap<>();
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        
        String clientIp = getClientIp(httpRequest);
        String requestPath = httpRequest.getRequestURI();
        
        if (requestPath.startsWith("/api/auth/")) {
            String key = clientIp + ":" + requestPath;
            
            if (isRateLimited(key)) {
                log.warn("Rate limit exceeded for IP: {}, Path: {}", clientIp, requestPath);
                httpResponse.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                httpResponse.getWriter().write("Too many requests. Please try again later.");
                return;
            }
        }
        
        chain.doFilter(request, response);
    }
    
    private boolean isRateLimited(String key) {
        long currentTime = System.currentTimeMillis();
        RequestCounter counter = requestCounts.computeIfAbsent(key, k -> new RequestCounter());
        
        synchronized (counter) {
            if (currentTime - counter.getWindowStart() > TimeUnit.SECONDS.toMillis(timeWindowSeconds)) {
                counter.reset(currentTime);
            }
            
            if (counter.getCount() >= maxRequests) {
                return true;
            }
            
            counter.increment();
            return false;
        }
    }
    
    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader != null) {
            return xfHeader.split(",")[0];
        }
        return request.getRemoteAddr();
    }
    
    private static class RequestCounter {
        private long windowStart;
        private int count;
        
        public RequestCounter() {
            this.windowStart = System.currentTimeMillis();
            this.count = 0;
        }
        
        public void reset(long currentTime) {
            this.windowStart = currentTime;
            this.count = 0;
        }
        
        public void increment() {
            this.count++;
        }
        
        public long getWindowStart() {
            return windowStart;
        }
        
        public int getCount() {
            return count;
        }
    }
}