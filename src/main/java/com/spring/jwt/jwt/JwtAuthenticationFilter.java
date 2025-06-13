package com.spring.jwt.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
                                    throws ServletException, java.io.IOException {
        // JWT doğrulama ve kullanıcı bilgilerini ayarlama işlemleri burada yapılacak
        // Örneğin, JWT'yi alıp doğrulamak ve kullanıcı bilgilerini SecurityContext'e eklemek

        String username;
        String token;
        String header = request.getHeader("Authorization");

        if(header==null) {
            filterChain.doFilter(request, response); // header yoksa işlem kesilir.
        }

        token = header.substring(7); // "Bearer " kısmını atla

        try {
           username = jwtService.getUserNameByToken(token);
           if(username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                if(userDetails != null && !jwtService.isTokenExpired(token)) {
                    // JWT geçerliyse, kullanıcı bilgilerini SecurityContext'e ekle
                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                    authenticationToken.setDetails(userDetails);
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }
            }
        } catch (ExpiredJwtException e) {
            System.out.println("Token expire: " + e.getMessage());
        }
        catch (Exception e) {
            System.out.println("Genel bir hata oluştu: " + e.getMessage());
        }

        filterChain.doFilter(request,response);
    }
}
