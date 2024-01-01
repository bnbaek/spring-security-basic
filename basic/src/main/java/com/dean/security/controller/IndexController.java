package com.dean.security.controller;

import com.dean.security.config.auth.PrincipalDetails;
import com.dean.security.model.User;
import com.dean.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Slf4j
@RequiredArgsConstructor

@Controller
public class IndexController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;


    @GetMapping("/test/login")
    public @ResponseBody String testLogin(Authentication authentication, @AuthenticationPrincipal PrincipalDetails userDetails){
      log.info("/test/login =============");
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
      log.info("authentication : {}", principalDetails.getUser());
      log.info("userDetails: {}",userDetails.getUser());
      return "세션정보 확인하기";
    }


    @GetMapping("/test/oauth/login")
    public @ResponseBody String testOauthLogin(Authentication authentication,@AuthenticationPrincipal OAuth2User oAuth2){
        log.info("/test/oauth/login =============");
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        log.info("OAuth2User authentication : {}", oAuth2User.getAttributes());
        log.info("Oauth authentication : {}", oAuth2.getAttributes());
//        log.info("userDetails: {}",userDetails.getUser());
        return "Oauth 세션정보 확인하기";
    }

    @GetMapping
    public @ResponseBody
    String index() {
        return "index";
    }

    @GetMapping("/user")
    public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        log.info("principalDetails {}",principalDetails);
        return "user";
    }

    @GetMapping("/admin")
    public @ResponseBody
    String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    public @ResponseBody
    String manager() {
        return "manager";
    }

    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    @PostMapping("/join")
    public  String join(User user) {
        user.setRole("ROLE_USER");
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);
        userRepository.save(user);
        //회원가입은 잘됨, 하지만 시큐리티로 로그인을 할수 없음 이유는 패스워드가 암호화가 안되였습니다.
        return "redirect:/loginForm";
    }

    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    public @ResponseBody String info(){
        return "개인정보";
    }

    @PreAuthorize("hasRole('ROLE_MANAGER') or hasAnyRole('ROLE_ADMIN')")
    @GetMapping("/data")
    public @ResponseBody String data(){
        return "데이터정보";
    }
//    @GetMapping("/joinProc")
//    public @ResponseBody
//    String joinProc() {
//        return "회원가입 완료됨!";
//    }
}
