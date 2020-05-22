package com.spring.security.api.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/rest/auth")
public class ApplicationController {

	/**
	 * Test with Auth
	 * @return
	 */
	@GetMapping("/getMsg")
	public String greeting() {
		return "spring security basic :Valid user::";
	}

}
