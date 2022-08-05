package com.ms.securitystudy.config;

import com.ms.securitystudy.jwt.JwtAccessDeniedHandler;
import com.ms.securitystudy.jwt.JwtAuthenticationEntryPoint;
import com.ms.securitystudy.jwt.JwtSecurityConfig;
import com.ms.securitystudy.jwt.TokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity // 기본적인 Web 보안을 활성화하겠다.
@EnableGlobalMethodSecurity(prePostEnabled = true) // @PreAuthorize 어노테이션을 메소드 단위로 추가하기 위해서 적용
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    // 추가적인 설정을 위해서 : implements WebSecurityConfigurer OR extends WebSecurityConfigurerAdaptor

    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private JwtAccessDeniedHandler jwtAccessDeniedHandler;

    public SecurityConfig(
            TokenProvider tokenProvider,
            JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
            JwtAccessDeniedHandler jwtAccessDeniedHandler) {
        this.tokenProvider = tokenProvider;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // PasswordEncoder 로 BCryptPasswordEncoder 사용
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web
                .ignoring()
                .antMatchers(
                        "/h2-console/**" // h2-console 요청과 파비콘 요청은 모두 무시
                        ,"/favicon.ico"
                );
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable() // token 을 사용하기 때문에 csrf 설정을 disable

                .exceptionHandling() // exception 을 핸들링할 때
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                .and() // h2-console 을 위한 설정 추가
                .headers()
                .frameOptions()
                .sameOrigin()

                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // session을 사용하지 않기 때문에 세션 설정을 Stateless

                .and()
                .authorizeRequests() // HttpServletRequest 를 사용하는 요청들에 대한 접근제한 설정
                .antMatchers("/api/hello").permitAll() // /api/hello 에 대한 요청은 인증없이 허용
                .antMatchers("/api/authenticate").permitAll() // 로그인 API
                .antMatchers("/api/signup").permitAll() // 회원가입 API
                .anyRequest().authenticated() // 나머지 요청에 대해서는 모두 인증을 받아야 함.

                .and()
                .apply(new JwtSecurityConfig(tokenProvider)); // JwtFilter 를 addFilterBefore로 등록했던 JwtSecurityConfig 적용
    }
}
