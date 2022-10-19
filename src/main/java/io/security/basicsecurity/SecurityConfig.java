package io.security.basicsecurity;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;


@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated(); // 인가 정책(사용자의 어떤 요청에도 인증 없을 시 접근 안됨)
        http
                .formLogin();

        http
                .logout()
                .logoutUrl("/logout") // Spring Security의 logout은 post 방식으로 처리
                .logoutSuccessUrl("/login")
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response,
                            Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate(); // 세션의 무효화 작업 처리

                    }
                }) // 로그아웃 시 처리되는 핸들러
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request,
                            HttpServletResponse response, Authentication authentication)
                            throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                }) // logoutSuccessUrl과 동일 - 이동 페이지만 정의, 핸들러 --> 많은 로직 처리
                .deleteCookies("remember-me") // remember-me 인증 시 해당 쿠키를 발급한다. --> 로그아웃 시 서버에서 만든 쿠키를 삭제하고 싶을 때 해당 이름의 쿠키가 삭제된다.
        ;
    }
}
