package com.myblog9.controller;

import com.myblog9.entity.Role;
import com.myblog9.entity.User;
import com.myblog9.payload.JWTAuthResponse;
import com.myblog9.payload.LoginDto;
import com.myblog9.payload.SignUpDto;
import com.myblog9.repository.RoleRepository;
import com.myblog9.repository.UserRepository;
import com.myblog9.security.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashSet;
import java.util.Set;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenProvider tokenProvider;

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@RequestBody SignUpDto signUpDto) {
        if (userRepository.existsByEmail(signUpDto.getEmail())) {
              new ResponseEntity<>("Email already exist - " + signUpDto.getEmail(), HttpStatus.INTERNAL_SERVER_ERROR);
        }

        if (userRepository.existsByUsername(signUpDto.getUsername())) {
          new ResponseEntity<>("Username already exist - " + signUpDto.getUsername(), HttpStatus.INTERNAL_SERVER_ERROR);
        }


        User user = new User();
        user.setName(signUpDto.getName());
        user.setEmail(signUpDto.getEmail());
        user.setUsername(signUpDto.getUsername());
        user.setPassword(passwordEncoder.encode(signUpDto.getPassword()));


//        //By default for all signup it create ADMIN Role
        Role roles = roleRepository.findByName("ROLE_ADMIN").get();
        Set<Role> role = new HashSet<>();
        role.add(roles);
        user.setRoles(role);

        userRepository.save(user);

        return new ResponseEntity<>("User is now registered!!", HttpStatus.CREATED);
    }



     //http://localhost:8080/api/auth/signin
    @PostMapping("/signin")
    public ResponseEntity<JWTAuthResponse> authenticateUser(@RequestBody LoginDto loginDto){

        //This part of the code is responsible for verifying username and passwords and accodingly behaving whether true or false
        Authentication authentication = authenticationManager.authenticate(new
                UsernamePasswordAuthenticationToken(                            // Authentication is responsible for getting username and password
                loginDto.getUsernameOrEmail(), loginDto.getPassword()));


        SecurityContextHolder.getContext().setAuthentication(authentication);         // if the user is valid then

        // get token form tokenProvider
        String token = tokenProvider.generateToken(authentication);                 // then this line will run      //we are generating the token for authentication user
        return ResponseEntity.ok(new JWTAuthResponse(token));
    }

    }
