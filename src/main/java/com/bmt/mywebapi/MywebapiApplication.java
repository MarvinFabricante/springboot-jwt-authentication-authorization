package com.bmt.mywebapi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class MywebapiApplication {

	public static void main(String[] args) {
		SpringApplication.run(MywebapiApplication.class, args);
		System.out.println("URL: http://localhost:7001");
	}

}
