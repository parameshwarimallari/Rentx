package com.rentx.carrental.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

@Data
@Component
@ConfigurationProperties(prefix = "app")
public class AppConfig {
    
    private Business business = new Business();
    private Loyalty loyalty = new Loyalty();
    private Cancellation cancellation = new Cancellation();
    
    @Data
    public static class Business {
        private String name;
        private Contact contact = new Contact();
        private String supportEmail;
        private String address;
        
        @Data
        public static class Contact {
            private String phone;
            private String email;
        }
    }
    
    @Data
    public static class Loyalty {
        private List<LoyaltyTier> tiers;
        
        @Data
        public static class LoyaltyTier {
            private int bookings;
            private double discount;
            private String name;
        }
    }
    
    @Data
    public static class Cancellation {
        private Refund refund = new Refund();
        
        @Data
        public static class Refund {
            private double refund48h;
            private double refund24h;
            private double refund0h;
        }
    }
}