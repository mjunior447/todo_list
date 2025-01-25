package br.com.mauantero.todolist.filter;

import br.com.mauantero.todolist.user.IUserRepository;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Base64;
import java.util.Objects;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {
    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // verifica a rota
        var servletPath = request.getServletPath();

        if (servletPath.equals("/tasks/")) {
            var authorization = request.getHeader("Authorization");
            var encodedPasswd = authorization.substring("Basic".length()).trim();
            byte[] decodedPasswd = Base64.getDecoder().decode(encodedPasswd);
            var authString = new String(decodedPasswd);

            String[] credentials = authString.split(":");
            String username = credentials[0];
            String password = credentials[1];

            var user = this.userRepository.findByUsername(username);

            if(user == null) {
                response.sendError(401);
            } else {
                // valida senha
                var verifiedPassword = Objects.equals(password, user.getPassword());

                if (verifiedPassword) {
                    filterChain.doFilter(request, response);
                } else {
                    response.sendError(401);
                }
            }
        } else {
            filterChain.doFilter(request, response);
        }


    }
}
