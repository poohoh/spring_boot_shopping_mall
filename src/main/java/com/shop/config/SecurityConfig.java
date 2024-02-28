package com.shop.config;

import com.shop.service.MemberService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

//    @Autowired
//    MemberService memberService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.formLogin()
                .loginPage("/members/login")  // 로그인 URL 설정
                .defaultSuccessUrl("/")  //로그인 성공 시 이동할 URL
                .usernameParameter("email")  // 로그인 시 사용할 파라미터 이름으로 email을 지정
                .failureUrl("/members/login/error");  // 로그인 실패 시 이동할 URL

        http.logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/members/logout"))  // 로그아웃 URL 설정
                .logoutSuccessUrl("/");  // 로그아웃 성공 시 이동할 URL 설정

        http.authorizeHttpRequests()
                .mvcMatchers("/",
                        "/members/**",
                        "/item/**",
                        "/images/**")
                .permitAll()
                .mvcMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated();

        http.exceptionHandling()
                .authenticationEntryPoint(new CustomAuthenticationEntryPoint());

        return http.build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().antMatchers("/css/**", "/js/**", "/img/**");
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // spring security에서 인증은 AuthenticationManager를 통해 이루어짐.
    // AuthenticationManagerBuilder가 AuthenticationManager를 생성.
    // userDetailService를 구현하고 있는 객체로 memberService를 지정해주며, 비밀번호 암호화를 위해 passwordEncoder 지정
    // 현재는 deprecated됨.
    // 이 상태에서 memberService를 어떻게 지정해주는지?

//    @Bean
//    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
//        throws Exception {
//        return authenticationConfiguration.getAuthenticationManager();
//    }
}
