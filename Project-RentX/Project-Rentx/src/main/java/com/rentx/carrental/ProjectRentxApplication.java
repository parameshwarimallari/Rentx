package com.rentx.carrental;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.scheduling.annotation.EnableScheduling;
@EnableScheduling
@SpringBootApplication
@ComponentScan(basePackages = "com.rentx.carrental")
public class ProjectRentxApplication {

	public static void main(String[] args) {
		SpringApplication.run(ProjectRentxApplication.class, args);
	}

}
