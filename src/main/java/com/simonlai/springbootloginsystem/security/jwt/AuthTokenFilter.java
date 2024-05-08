package com.simonlai.springbootloginsystem.security.jwt;

import com.simonlai.springbootloginsystem.security.service.UserDetailsImpl;
import com.simonlai.springbootloginsystem.security.service.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class AuthTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    // Define logger
    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            // Obtain jwt from request
            String jwt = parseJwt(request);

            // Jwt exists and jwt token is valid
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
                // Obtain username from jwt
                String username = jwtUtils.getUserNameFromJwtToken(jwt);
                // Obtain userDetails
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                // Build token
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                // Set token detail
                authenticationToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                // Register to the security context, make sure the user has auth. successfully
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        } catch (Exception e) {
            logger.error("Cannot set user authentication token: {}", e);
        }

        filterChain.doFilter(request, response);
    }


    // Obtain jwt from cookies
    private String parseJwt(HttpServletRequest request) {
        return jwtUtils.getJwtFromCookies(request);
    }
}
