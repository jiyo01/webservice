package com.example.config.auth;

import com.example.domain.user.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@RequiredArgsConstructor
@EnableWebSecurity      //Spring Security 설정들을 활성화한다.
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomOAuth2UserService customOAuth2UserService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .headers().frameOptions().disable() //h2-console 화면을 사용하기 위해 해당 옵션들을 disable 한다.
                .and()
                .authorizeRequests()
                .antMatchers("/", "/css/**", "/images/**",
                        "/js/**", "/h2-console/**", "/profile").permitAll()     //해당 URL들은 permitAll()을 통해 인증(로그인) 없이 접근할 수 있도록 설정한다.
                .antMatchers("/api/v1/**").hasRole(Role.USER.name())  //"/api/v1/**"요청은 USER 권한을 가진 사람만 접근 가능하도록 한다.
                .anyRequest().authenticated() //그 외 모든 요청은 인증된 사용자만 접근 가능
                .and()
                .logout()
                .logoutSuccessUrl("/")       //로그아웃 성공 시 이동할 URL을 설정
                .and()
                .oauth2Login()
                .userInfoEndpoint()         //OAuth2 로그인 성공 이후 사용자 정보를 가져올 때의 설정들을 담당한다.
                .userService(customOAuth2UserService); //소셜 로그인 성공 시 후속 조치를 진행할 UserService 인터페이스의 구현체를 등록한다.
    }
}
