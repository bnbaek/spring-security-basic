package com.dean.security.config.oauth;

import com.dean.security.config.auth.PrincipalDetails;
import com.dean.security.model.User;
import com.dean.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor

@Slf4j
@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {
//    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("userRequest {}", userRequest.getClientRegistration());
        log.info("userRequest {}", userRequest.getAccessToken().getTokenValue());
        OAuth2User oauth2User = super.loadUser(userRequest);

        log.info("userRequest {}", oauth2User.getAttributes());

        //구글로그인버튼 클릭->구글로그인창 ->로그인완료->code를 리턴(oauth-client라이브러리)->acceestoken요청
        //userRequest정보-> loadUser함수를 호출->구글로부터 회원프로필 받아준다.

//        {sub=111095616401048600367
//        , name=dean mateo, given_name=dean
//        , family_name=mateo,
//        picture=https://lh3.googleusercontent.com/a/ACg8ocL3h_gdApWdXkpplx9MT5woC0hy-CTER6yZXL1d5W34=s96-c,
//        email=iopenu@gmail.com, email_verified=true,
//        locale=ko}

        String provider = userRequest.getClientRegistration().getClientId();    //google
        String providerId = oauth2User.getAttribute("sub");
        String username = provider + "+" + providerId;
        String password = "hello";
        String email = oauth2User.getAttribute("email");
        String role = "ROLE_USER";

        User userEntity = userRepository.findByUsername(username);
        if (userEntity == null) {
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build()
            ;
            ;
            userRepository.save(userEntity);
        }


        return new PrincipalDetails(userEntity,oauth2User.getAttributes());
    }
}
