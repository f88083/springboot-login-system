package com.simonlai.springbootloginsystem.security.jwt;

import com.simonlai.springbootloginsystem.security.service.UserDetailsImpl;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {
    // Define logger
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    // Inject values from application.properties
    @Value("${simonlai.app.jwtSecret}")
    private String jwtSecret;

    @Value("${simonlai.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    @Value("${simonlai.app.jwtCookieName}")
    private String jwtCookie;

    public String getJwtFromCookies(HttpServletRequest request) {
        // Obtain cookie
        Cookie cookie = WebUtils.getCookie(request, jwtCookie);

        // Cookie with the specified name "jwtCookie" exists
        if (cookie != null) {
            return cookie.getValue();
        } else {
            return null;
        }
    }

    // Generate new Jwt token for the provided UserDetailsImpl obj.
    public ResponseCookie generateJwtCookie(UserDetailsImpl userPrincipal) {
        // Generate the new jwt token using username
        String jwt = generateTokenFromUsername(userPrincipal.getUsername());
        return ResponseCookie.from(jwtCookie, jwt)
                .path("/api") // cookie path
                .maxAge(24 * 60 * 60) // 24 hrs
                .httpOnly(true)
                .build();
    }

    // Generate simple jwt cookie with the name "jwtCookie" and path only
    public ResponseCookie getCleanJwtCookie() {
        return ResponseCookie.from(jwtCookie, null)
                .path("/api")
                .build();
    }

    // Obtain username from jwt token
    public String getUserNameFromJwtToken(String token) {
        return Jwts.parserBuilder().setSigningKey(key()).build()
                .parseClaimsJws(token).getBody().getSubject();
    }

    // Generate key from jwtSecret
    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    // Jwt token validator
    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parserBuilder().setSigningKey(key()).build().parse(authToken);
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }

    // Generate token from username with details
    private String generateTokenFromUsername(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(new Date().getTime() + jwtExpirationMs))
                .signWith(key(), SignatureAlgorithm.HS256)
                .compact();
    }
}
