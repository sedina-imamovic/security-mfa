package bih.iths.sedina.mfasecurity.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class TwoFactorFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();

        if (path.equals("/verify-2fa")
                || path.equals("/login")
                || path.equals("/logout")
                || path.equals("/register")
                || path.equals("/qr")
                || path.startsWith("/css")) {
            filterChain.doFilter(request, response);
            return;
        }

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth != null && auth.isAuthenticated() && !"anonymousUser" .equals(auth.getPrincipal())) {

            HttpSession session = request.getSession(false);
            Boolean verified = (session != null) ? (Boolean) session.getAttribute("2fa_verified") : null;

            if (verified == null || !verified) {

                if (path.equals("/post-login")) {
                    filterChain.doFilter(request, response);
                    return;
                }

                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied: 2FA Verification Required");
                return;
            }
        }
        filterChain.doFilter(request, response);
    }
}