package com.perfumepedia.perfumepedia.global.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;

@Component
public class JwtTokenProvider {

    private Key secretKey;

    @Value("${jwt.secret}")
    private String base64SecretKey;

    private final long ACCESS_TOKEN_VALIDITY = 30 * 60 * 1000L; // 30분
    private final long REFRESH_TOKEN_VALIDITY = 7 * 24 * 60 * 60 * 1000L; // 7일

    @PostConstruct
    protected void init() {
        secretKey = Keys.hmacShaKeyFor(Base64.getDecoder().decode(base64SecretKey));
    }

    // Access Token 생성
    public String createAccessToken(String email, String role) {
        return createToken(email, role, ACCESS_TOKEN_VALIDITY);
    }

    // Refresh Token 생성
    public String createRefreshToken(String email, String role) {
        return createToken(email, role, REFRESH_TOKEN_VALIDITY);
    }

    // 토큰 생성
    private String createToken(String email, String role, long expireTime) {
        Claims claims = Jwts.claims().setSubject(email).build();
        claims.put("role", role);

        Date now = new Date();
        Date validity = new Date(now.getTime() + expireTime);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    // 토큰에서 이메일 추출
    public String getEmail(String token) {
        return Jwts.parser() // 레거시 방식 사용
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    // 토큰 검증
    public boolean validateToken(String token) {
        try {
            Jwts.parser() // 레거시 방식 사용
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // 인증 객체 생성
    public Authentication getAuthentication(String token) {
        String email = getEmail(token);
        return new UsernamePasswordAuthenticationToken(
                email, "", Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
    }

    // 요청에서 토큰 추출
    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7); // "Bearer " 제거 후 반환
        }
        return null;
    }
}
