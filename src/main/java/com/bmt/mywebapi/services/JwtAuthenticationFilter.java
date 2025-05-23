package com.bmt.mywebapi.services;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// this filter class allows us to verify if the jwt is valid or not

@Service
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AppUserService appUserService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        try {
            String bearerToken = request.getHeader("Authorization");
            if (bearerToken == null || !bearerToken.startsWith("Bearer ")) {
                throw new Exception("Authorization Bearer not found");
            }

            String jwt = bearerToken.substring(7); // remove Bearer prefix
            Claims claims = jwtService.getTokenClaims(jwt);

            if (claims == null) {
                throw new Exception("Token is not valid");
            }

            // jwt is valid
            String email = claims.getSubject();
            var userDetails = appUserService.loadUserByUsername(email);

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, null);

            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (Exception ex) {
            System.out.println("Cannot authenticate user: " + ex.getMessage());
        }

        filterChain.doFilter(request, response);
    }
}
