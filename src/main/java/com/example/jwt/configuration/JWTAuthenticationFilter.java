package com.example.jwt.configuration;

import ch.qos.logback.core.util.StringUtil;
import com.example.jwt.util.JwtUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class JWTAuthenticationFilter extends OncePerRequestFilter {

    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //Fetch token from request
        var jwtTokenOptional = gettokenFromRequest(request);

        //Validate jwt token -> JWT utils
        jwtTokenOptional.ifPresent(jwtToken -> {
            if (JwtUtils.validateToken(jwtToken)) {
                var usernameOptional = JwtUtils.getUserNameFromToken(jwtToken);

                usernameOptional.ifPresent(username -> {
                    //Fetch user details with the help of username
                    var userDetails = userDetailsService.loadUserByUsername(username);

                    //Create Authentication Token
                    var authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    //set authentication token to Security Context
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                });

            }
        });
        //Pass request and response to next filter
        filterChain.doFilter(request, response);
    }

    private Optional<String> gettokenFromRequest(HttpServletRequest request) {
        //Extract authentication Header
        var authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        //Bearer <JWT Token>
        if (StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
            return Optional.of(authHeader.substring(7));
        }

        return Optional.ofNullable(null);
    }
}
