package com.dean.security.config;

import com.dean.security.config.oauth.PrincipalOauth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;


@RequiredArgsConstructor

@Configuration
@EnableWebSecurity  //스프링 시큐리티 필터가 스프링 필터체인에 등록이 됩니다.
@EnableGlobalMethodSecurity(securedEnabled = true,prePostEnabled = true)     //secured 어노테이션 활성화, preAuthorize,postAuthorize 어노테이션 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final PrincipalOauth2UserService principalOauth2UserService;

    @Bean
    public BCryptPasswordEncoder encodePwd(){
        return  new BCryptPasswordEncoder();
    }
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated()
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
                .and()
                .formLogin()
                .loginPage("/loginForm")
//                .usernameParameter("username2")
                .loginProcessingUrl("/login")   //login주소가 호출이 되면 시크리티가 낚아채서 대신 로그인을 진행해줍니다.
                .defaultSuccessUrl("/")
                .and()
                .oauth2Login()
                .loginPage("/loginForm")        //구글 로그인이 완료된 두에 후처리가 필요함
                // 1. 코드받기(인증)
                // 2. 액세스토큰(권한)
                // , 3.사용필 프로필정보를 가져와서
                // 4. 그정보를 토대로 회원가입을 자동으로 진행 - 코드 x(엑세스토큰_사용자프로필정보 o)
                // 4-2. (이메일, 전화번호, 이름, 아이디) 쇼필몰 -> 집수소, 백화점몰 -vip
                .userInfoEndpoint()
                .userService(principalOauth2UserService)
        ;

    }
}
