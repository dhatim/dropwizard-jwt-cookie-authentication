package org.dhatim.dropwizard.jwt.cookie.authentication;

import org.hibernate.validator.constraints.NotEmpty;

public class JwtCookieAuthConfiguration {
    
    private String secretSeed;
    
    private boolean httpsOnlyCookie = false;
    
    @NotEmpty
    private String sessionExpiryVolatile = "PT30m";
    
    @NotEmpty
    private String sessionExpiryPersistent = "P7d";

    public String getSecretSeed() {
        return secretSeed;
    }

    public boolean isHttpsOnlyCookie() {
        return httpsOnlyCookie;
    }

    public String getSessionExpiryVolatile() {
        return sessionExpiryVolatile;
    }

    public String getSessionExpiryPersistent() {
        return sessionExpiryPersistent;
    }
}
