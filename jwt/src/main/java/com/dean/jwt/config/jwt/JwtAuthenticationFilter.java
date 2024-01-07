package com.dean.jwt.config.jwt;

import com.dean.jwt.config.auth.PrincipalDetails;
import com.dean.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;

//스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음
//login 요청해서 username,password 전송하면 동작 (post)

@Slf4j

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    //login요청을 하면 로그인 시도를 위해서 실행하는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.info("JwtAuthenticationFilter: 로그인 시도중");
        //1. username,password를 받아서
        try {
//            BufferedReader br = request.getReader();
//            String input = null;
//            while ((input = br.readLine()) != null) {
//                log.info("{}", input);
//            }
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            log.info("user {}",user);

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
            //PrincipalDetailsService의 loadUserByUsername() 함수가 실행됨
            Authentication authenticate = authenticationManager.authenticate(authenticationToken);

            PrincipalDetails principalDetails = (PrincipalDetails) authenticate.getPrincipal();
            log.info("로그인완료됨 {}",principalDetails.getUser().getUsername());

            return authenticate;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        //2. 정상인지 로그인 시도를 해보는 거예요. authenticationManager로 로그인시도를 하면
        //PrincipalDetailsService가 호출이 된다.

        //3. PrincipaDetails를 세션에 담고(권한 관리를 위해서)
        //4. JWT토큰을 만들어서 응답해주면 됨
//        return super.attemptAuthentication(request, response);
    }

    //attemptAuthentication 싱행후 인증이 정상적으로 안료되면 싱행

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        log.info("successfulAuthentication 실행 ");
        super.successfulAuthentication(request, response, chain, authResult);
    }
}
