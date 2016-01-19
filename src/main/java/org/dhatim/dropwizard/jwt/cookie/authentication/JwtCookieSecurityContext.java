package org.dhatim.dropwizard.jwt.cookie.authentication;

import java.security.Principal;
import javax.ws.rs.core.SecurityContext;

public class JwtCookieSecurityContext implements SecurityContext{

    private final Subject subject;
    private final boolean secure;

    public JwtCookieSecurityContext(Subject subject, boolean secure) {
        this.subject = subject;
        this.secure = secure;
    }
    
    @Override
    public Principal getUserPrincipal() {
        return subject;
    }

    @Override
    public boolean isUserInRole(String role) {
        return subject.hasRole(role);
    }

    @Override
    public boolean isSecure() {
        return secure;
    }

    @Override
    public String getAuthenticationScheme() {
        return "JWT_COOKIE";
    }
    
}
