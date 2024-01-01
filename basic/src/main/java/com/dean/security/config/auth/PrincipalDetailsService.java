package com.dean.security.config.auth;

import com.dean.security.model.User;
import com.dean.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

//security 설정에서 loginProcessingUser("/login");
//login요청이 오면 자동으로 UserDetailsService타입으로 ioc되어 있는 loaduserByUsername함수가 실행
@RequiredArgsConstructor
@Service
public class PrincipalDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    //시큐리티 session( Authentication(내부 UserDetails) )
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User userEntity = userRepository.findByUsername(username);

        if(userEntity!=null){
            return new PrincipalDetails(userEntity);
        }
        return null;
    }
}
