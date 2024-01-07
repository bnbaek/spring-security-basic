package com.dean.jwt.config.auth;

import com.dean.jwt.model.User;
import com.dean.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Slf4j

//http://loclahost:8080/login요청할때 동작한다.
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {
    private final UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        log.info("principalDetailsService의 loadUserByUsername()");
        User userEntity = userRepository.findByUsername(username);
        log.info("userEntity {}",userEntity);
        return new PrincipalDetails(userEntity);
    }
}
