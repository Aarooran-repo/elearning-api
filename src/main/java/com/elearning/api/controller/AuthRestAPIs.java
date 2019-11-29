package com.elearning.api.controller;

import java.util.HashSet;
import java.util.Set;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.elearning.api.message.request.LoginForm;
import com.elearning.api.message.request.SignUpForm;
import com.elearning.api.message.response.JwtResponse;
import com.elearning.api.message.response.ResponseMessage;
import com.elearning.api.model.ConfirmationToken;
import com.elearning.api.model.Role;
import com.elearning.api.model.RoleName;
import com.elearning.api.model.User;
import com.elearning.api.repository.ConfirmationTokenRepository;
import com.elearning.api.repository.RoleRepository;
import com.elearning.api.repository.UserRepository;
import com.elearning.api.security.jwt.JwtProvider;
import com.elearning.api.services.EmailSenderService;
import com.elearning.api.services.MailClient;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthRestAPIs {
	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	UserRepository userRepository;
	@Autowired
	MailClient mailClientService;

	@Autowired
	RoleRepository roleRepository;

	@Autowired
	PasswordEncoder encoder;

	@Autowired
	JwtProvider jwtProvider;

	@Autowired
	private EmailSenderService emailSenderService;

	@Autowired
	private ConfirmationTokenRepository confirmationTokenRepository;

	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginForm loginRequest) {

		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

		SecurityContextHolder.getContext().setAuthentication(authentication);

		String jwt = jwtProvider.generateJwtToken(authentication);
		UserDetails userDetails = (UserDetails) authentication.getPrincipal();

		return ResponseEntity.ok(new JwtResponse(jwt, userDetails.getUsername(), userDetails.getAuthorities()));
	}

	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpForm signUpRequest) {
//		if (userRepository.existsByUsername(signUpRequest.getUsername())) {
//			return new ResponseEntity<>(new ResponseMessage("Fail -> Username is already taken!"),
//					HttpStatus.BAD_REQUEST);
//		}

		if (userRepository.existsByEmail(signUpRequest.getEmail())) {
			return new ResponseEntity<>(new ResponseMessage("Fail -> Email is already in use!"),
					HttpStatus.BAD_REQUEST);
		}

		// Creating user's account
		User user = new User(signUpRequest.getFirstName(), signUpRequest.getLastName(), signUpRequest.getEmail(),
				encoder.encode(signUpRequest.getPassword()));

		Set<String> strRoles = signUpRequest.getRole();
		Set<Role> roles = new HashSet<>();

		strRoles.forEach(role -> {
			switch (role) {
			case "admin":
				Role adminRole = roleRepository.findByName(RoleName.ROLE_ADMIN)
						.orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
				roles.add(adminRole);

				break;
			case "pm":
				Role pmRole = roleRepository.findByName(RoleName.ROLE_PM)
						.orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
				roles.add(pmRole);

				break;
			default:
				Role userRole = roleRepository.findByName(RoleName.ROLE_USER)
						.orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
				roles.add(userRole);
			}
		});

		user.setRoles(roles);
		userRepository.save(user);

		ConfirmationToken confirmationToken = new ConfirmationToken(user);
		confirmationTokenRepository.save(confirmationToken);
		
		mailClientService.prepareAndSend(user.getEmail(), "To confirm your account, please click here : "
				+ "http://localhost:8081/api/auth/confirm-account?token=" + confirmationToken.getConfirmationToken());

		/*SimpleMailMessage mailMessage = new SimpleMailMessage();
		mailMessage.setTo(user.getEmail());
		mailMessage.setSubject("Complete Registration!");
		mailMessage.setFrom("aaroor2015@gmail.com");
		mailMessage.setText("To confirm your account, please click here : "
				+ "http://localhost:8081/api/auth/confirm-account?token=" + confirmationToken.getConfirmationToken());

		emailSenderService.sendEmail(mailMessage);*/

		return new ResponseEntity<>(new ResponseMessage("User registered successfully!" + "\n"
				+ "To confirm your account, please click here : \"\r\n"
				+ "        +\"http://localhost:8081/api/auth/confirm-account?token=\"+confirmationToken.getConfirmationToken()"),
				HttpStatus.OK);
	}

	@RequestMapping(value = "/confirm-account", method = { RequestMethod.GET, RequestMethod.POST })
	public ResponseEntity<?> confirmUserAccount(@RequestParam("token") String confirmationToken) {
		ConfirmationToken token = confirmationTokenRepository.findByConfirmationToken(confirmationToken);

		if (token != null) {
			User user = userRepository.findByEmailIgnoreCase(token.getUser().getEmail());
			user.setEnabled(true);
			userRepository.save(user);
			return new ResponseEntity<>(new ResponseMessage("Account Verified!"), HttpStatus.OK);
		} else {
			return new ResponseEntity<>(new ResponseMessage("Account Not Verified!"), HttpStatus.BAD_GATEWAY);
		}
	}

}
