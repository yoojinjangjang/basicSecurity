package io.security.basicsecurity;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;


@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated(); // 인가 정책(사용자의 어떤 요청에도 인증 없을 시 접근 안됨)
        http
                .formLogin()
                //.loginPage("/loginPage")  // 인증 필요시 나의 로그인 페이지로 이동
                .defaultSuccessUrl("/")
                .failureUrl("/login")
                .usernameParameter("userId")
                .passwordParameter("passwd")
                .loginProcessingUrl("/login_proc") // form tag의 action url
//                .successHandler(new AuthenticationSuccessHandler() {
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest request,
//                            HttpServletResponse response, Authentication authentication)
//                            throws IOException, ServletException {
//                        // request, response, authentication -- 인증에 성공했을 때 최종적으로 인증한 결과를 담은 인증 객체 파라미터 전달
//                        System.out.println("authentication: " + authentication.getName());
//                        response.sendRedirect("/"); // 인증 성공 후 root 페이지 이동
//                    }
//                })
//                .failureHandler(new AuthenticationFailureHandler() {
//                    @Override
//                    public void onAuthenticationFailure(HttpServletRequest request,
//                            HttpServletResponse response, AuthenticationException exception)
//                            throws IOException, ServletException {
//                        // 인증 실패 시 인증 예외를 파라미터로 전달
//                        System.out.println("exceptiion" + exception.getMessage());
//                        response.sendRedirect("/login");
//                    }
//                })
                .permitAll() // 위의 경로 (loginPage)의 접근은 인증을 받지 않아도 가능

        ;                  // 인증 정책
    }
}
