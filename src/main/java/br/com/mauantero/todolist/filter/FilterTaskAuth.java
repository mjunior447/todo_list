package br.com.mauantero.todolist.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Base64;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        var authorization = request.getHeader("Authorization");
        var encodedPasswd = authorization.substring("Basic".length()).trim();
        byte[] decodedPasswd = Base64.getDecoder().decode(encodedPasswd);
        var authString = new String(decodedPasswd);

        String[] credentials = authString.split(":");
        String username = credentials[0];
        String password = credentials[1];

        filterChain.doFilter(request, response);
    }
}
