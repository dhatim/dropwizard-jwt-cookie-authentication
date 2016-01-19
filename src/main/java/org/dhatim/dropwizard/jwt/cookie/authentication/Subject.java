package org.dhatim.dropwizard.jwt.cookie.authentication;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.jsonwebtoken.Claims;
import java.security.Principal;

public class Subject implements Principal{
    
    private final static String LONG_TERM = "ltt"; // long-term token == rememberme
    
    protected final Claims claims;

    public Subject(@JsonProperty("claims") Claims claims) {
        this.claims = claims;
    }

    public Claims getClaims() {
        return claims;
    }
    
    public boolean hasRole(String role){
        return true;
    }
    
    public boolean isLongTermToken(){
        return claims.get(LONG_TERM) == Boolean.TRUE;
    }
    
    public Subject setLongTermToken(boolean longTerm){
        claims.put(LONG_TERM, longTerm);
        return this;
    }

    @Override
    public String getName() {
        return (String) claims.getSubject();
    }
    
    public void setName(String name) {
        claims.setSubject(name);
    }
}
