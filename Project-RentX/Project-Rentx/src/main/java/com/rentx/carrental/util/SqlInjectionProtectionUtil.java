package com.rentx.carrental.util;

import org.springframework.stereotype.Component;

@Component
public class SqlInjectionProtectionUtil {
    
    private static final String[] SQL_INJECTION_PATTERNS = {
        "'.*--",     
        "'.*;",       
        "'.*\\b(OR|AND)\\b.*=", 
        "'.*\\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\\b",
        "'.*\\b(UNION)\\b",
        "'.*\\b(WHERE)\\b",
        "'\\s*\\b(OR)\\b\\s+'.*'='",
        "'\\s*\\b(AND)\\b\\s+'.*'='"
    };
    
    public static boolean containsSqlInjection(String input) {
        if (input == null || input.trim().isEmpty()) {
            return false;
        }
        
        String upperInput = input.toUpperCase();
        for (String pattern : SQL_INJECTION_PATTERNS) {
            if (upperInput.matches(pattern)) {
                return true;
            }
        }
        return false;
    }
    
    public static String sanitizeInput(String input) {
        if (input == null) return null;
        
        return input.replaceAll("[';\"\\\\]", "");
    }
    
    public static String sanitizeLikeParameter(String input) {
        if (input == null) return null;
        
        return input.replace("!", "!!")
                   .replace("%", "!%")
                   .replace("_", "!_")
                   .replace("[", "![");
    }
}