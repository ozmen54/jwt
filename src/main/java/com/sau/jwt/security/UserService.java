package com.sau.jwt.security;

import com.sau.jwt.DTOs.LoginRequest;
import com.sau.jwt.model.User;
import com.sau.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final JwtUtility jwtUtility;
    private final AuthenticationManager authenticationManager;

    public String loginAndCreateAuthenticationToken(LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        return jwtUtility.createToken(authentication);
    }

    public void createUser(User user) {
        userRepository.save(user);
    }
}
