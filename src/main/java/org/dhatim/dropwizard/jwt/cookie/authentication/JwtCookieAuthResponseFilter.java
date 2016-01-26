/**
 * Copyright 2016 Dhatim
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.dhatim.dropwizard.jwt.cookie.authentication;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.io.IOException;
import java.security.Key;
import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.function.Function;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;

class JwtCookieAuthResponseFilter<P extends JwtCookiePrincipal> implements ContainerResponseFilter {

    private static final String COOKIE_TEMPLATE_INSECURE = "=%s; Path=/;";
    private static final String COOKIE_TEMPLATE_SECURE = COOKIE_TEMPLATE_INSECURE + " secure";
    private static final String DELETE_COOKIE_TEMPLATE = "=; Path=/; expires=Thu, 01-Jan-70 00:00:00 GMT";

    private final Class<P> principalType;
    private final Function<P, Claims> serializer;
    private final String cookieName;
    private final String sessionCookieFormat;
    private final String persistentCookieFormat;
    private final String deleteCookie;

    private final Key signingKey;
    private final int volatileSessionDuration; //in seconds
    private final int persistentSessionDuration;

    public JwtCookieAuthResponseFilter(
            Class<P> principalType,
            Function<P, Claims> serializer,
            String cookieName,
            boolean httpsOnly,
            Key signingKey,
            int volatileSessionDuration,
            int persistentSessionDuration) {

        this.principalType = principalType;
        this.serializer = serializer;
        this.cookieName = cookieName;
        this.sessionCookieFormat = cookieName
                + (httpsOnly
                        ? COOKIE_TEMPLATE_SECURE
                        : COOKIE_TEMPLATE_INSECURE);
        this.persistentCookieFormat = sessionCookieFormat + " Max-Age=%d;";
        this.deleteCookie = cookieName + DELETE_COOKIE_TEMPLATE;
        this.signingKey = signingKey;
        this.volatileSessionDuration = volatileSessionDuration;
        this.persistentSessionDuration = persistentSessionDuration;
    }

    @Override
    public void filter(ContainerRequestContext request, ContainerResponseContext response) throws IOException {
        Principal principal = request.getSecurityContext().getUserPrincipal();
        if (request.getSecurityContext() instanceof JwtCookieSecurityContext) {
            if (principalType.isInstance(principal)) {
                if (request.getProperty(DontRefreshSessionFilter.DONT_REFRESH_SESSION_PROPERTY) != Boolean.TRUE) {
                    P cookiePrincipal = (P) principal;
                    String cookie = cookiePrincipal.isPersistent()
                            ? String.format(persistentCookieFormat, getJwt(cookiePrincipal, persistentSessionDuration), persistentSessionDuration)
                            : String.format(sessionCookieFormat, getJwt(cookiePrincipal, volatileSessionDuration));

                    response.getHeaders().add("Set-Cookie", cookie);
                }
            } else if (request.getCookies().containsKey(cookieName)) {
                //the principal has been unset during the response, delete the cookie
                response.getHeaders().add("Set-Cookie", deleteCookie);
            }
        }
    }

    private String getJwt(P subject, int expiresIn) {
        return Jwts.builder()
                .signWith(SignatureAlgorithm.HS256, signingKey)
                .setClaims(serializer.apply(subject))
                .setExpiration(Date.from(Instant.now().plus(expiresIn, ChronoUnit.SECONDS)))
                .compact();
    }

}
