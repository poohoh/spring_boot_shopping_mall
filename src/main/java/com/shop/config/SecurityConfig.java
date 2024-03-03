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
        http.formLogin((formLogin) ->
                formLogin
                        .loginPage("/members/login")  // 로그인 URL 설정
                        .defaultSuccessUrl("/")  //로그인 성공 시 이동할 URL
                        .usernameParameter("email")  // 로그인 시 사용할 파라미터 이름으로 email을 지정
                        .failureUrl("/members/login/error")  // 로그인 실패 시 이동할 URL
        );

        http.logout((logout) ->
                logout
                        .logoutRequestMatcher(new AntPathRequestMatcher("/members/logout"))  // 로그아웃 URL 설정
                        .logoutSuccessUrl("/")  // 로그아웃 성공 시 이동할 URL 설정
        );

        http.authorizeHttpRequests((authorizeRequest) ->  // 시큐리티 처리에 HttpServiceRequest를 이용
                authorizeRequest
                        .requestMatchers("/", "/members/**", "/item/**", "/images/**").permitAll()  // 모든 사용자가 인증 없이 해당 경로에 접근할 수 있게 설정
                        .requestMatchers("/admin/**").hasRole("ADMIN")  // /admin으로 시작하는 경로는 해당 계정이 ADMIN role일 경우에만 가능
                        .anyRequest().authenticated()  // 앞서 설정한 경로를 제외한 나머지 경로들은 모두 인증을 요
        );

        http.exceptionHandling((exception) ->
                exception
                        .authenticationEntryPoint(new CustomAuthenticationEntryPoint())  // 인증되지 않은 사용자가 리소스에 접근한 경우 수행되는 핸들러 등록
        );

        return http.build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers("/css/**", "/js/**", "/img/**");  // static directory의 하위 파일은 인증을 무시
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // spring security에서 인증은 AuthenticationManager를 통해 이루어짐.
    // AuthenticationManagerBuilder가 AuthenticationManager를 생성.
    // userDetailService를 구현하고 있는 객체로 memberService를 지정해주며, 비밀번호 암호화를 위해 passwordEncoder 지정

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
        throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
