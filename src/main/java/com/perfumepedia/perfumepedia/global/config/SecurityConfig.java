package com.perfumepedia.perfumepedia.global.config;

import com.perfumepedia.perfumepedia.global.utils.JwtTokenProvider;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {


	private final JwtTokenProvider jwtTokenProvider;

	/**
	 * 패스워드 암호화를 위한 인코더 빈 등록
	 */
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
		return httpSecurity
				.csrf(csrf -> csrf.disable()) // CSRF 비활성화
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 세션 비활성화
				.authorizeHttpRequests(authorizeRequests -> authorizeRequests
						.requestMatchers("/auth/**").permitAll() // 인증 없이 접근 허용
						.anyRequest().authenticated() // 나머지 요청은 인증 필요
				)
				.addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class) // JWT 필터 등록
				.exceptionHandling(exception -> exception
						.authenticationEntryPoint((request, response, authException) -> {
							response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
							response.getWriter().write("Unauthorized: " + authException.getMessage());
						})
						.accessDeniedHandler((request, response, accessDeniedException) -> {
							response.setStatus(HttpServletResponse.SC_FORBIDDEN);
							response.getWriter().write("Access Denied: " + accessDeniedException.getMessage());
						})
				)
				.build();
	}
}
