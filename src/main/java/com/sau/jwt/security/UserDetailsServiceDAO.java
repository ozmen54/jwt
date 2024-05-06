package com.sau.jwt.security;

import com.sau.jwt.model.User;
import com.sau.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceDAO implements UserDetailsService {
    private final UserRepository ur;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = ur.getReferenceByUname(username);
        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .roles(user.getRole())
                .accountLocked(user.isLocked())
                .disabled(false)
                .credentialsExpired(false)
                .build();
    }
}
