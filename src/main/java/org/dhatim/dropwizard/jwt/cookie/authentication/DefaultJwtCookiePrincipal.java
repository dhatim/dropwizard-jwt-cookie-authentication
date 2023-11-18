/**
 * Copyright 2023 Dhatim
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.dhatim.dropwizard.jwt.cookie.authentication;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ClaimsBuilder;
import io.jsonwebtoken.Jwts;

import java.util.Collection;
import java.util.Collections;
import java.util.Optional;

/**
 * Default implementation of JwtCookiePrincipal
 */
public class DefaultJwtCookiePrincipal implements JwtCookiePrincipal {

    private final static String PERSISTENT = "pst"; // long-term token == rememberme
    private final static String ROLES = "rls";

    protected final ClaimsBuilder claimsBuilder;

    /**
     * Builds a new instance of DefaultJwtCookiePrincipal
     *
     * @param name       the principal name
     * @param persistent if the cookie must be persistent
     * @param roles      the roles the principal is in
     * @param claims     custom data associated with the principal
     */
    public DefaultJwtCookiePrincipal(
            @JsonProperty("name") String name,
            @JsonProperty("persistent") boolean persistent,
            @JsonProperty("roles") Collection<String> roles,
            @JsonProperty("claims") Claims claims) {
        this.claimsBuilder = Jwts.claims();
        if (claims != null) {
            claimsBuilder.add(claims);
        }
        claimsBuilder.subject(name).add(PERSISTENT, persistent).add(ROLES, roles);
    }

    /**
     * Build a new instance of DefaultJwtCookiePrincipal with the given name
     *
     * @param name the name
     */
    public DefaultJwtCookiePrincipal(String name) {
        this(name, false, Collections.emptyList(), null);
    }

    /**
     * Build a new instance of DefaultJwtCookiePrincipal from the JWT claims
     *
     * @param claims the JWT claims
     */
    public DefaultJwtCookiePrincipal(Claims claims) {
        this.claimsBuilder = Jwts.claims();
        if (claims != null) {
            claimsBuilder.add(claims);
        }
    }

    /**
     * Get the claims used to serialize this principal
     *
     * @return the claims
     */
    public Claims getClaims() {
        return claimsBuilder.build();
    }

    /**
     * Indicates if this principal has the given role
     *
     * @param role the role
     * @return true if the principal is in the given role, false otherwise
     */
    @Override
    public boolean isInRole(String role) {
        return getRoles().contains(role);
    }

    /**
     * Get a collection of all the roles this principal is in
     *
     * @return the roles
     */
    public Collection<String> getRoles() {
        return Optional.ofNullable(getClaims().get(ROLES))
                .map(Collection.class::cast)
                .orElse(Collections.emptyList());
    }

    /**
     * Set the roles this principal is in
     *
     * @param roles the roles
     */
    public void setRoles(Collection<String> roles) {
        claimsBuilder.add(ROLES, roles);
    }

    /**
     * Indicates if the cookie must be persistent
     *
     * @return if the cookie must be persistent
     */
    @Override
    public boolean isPersistent() {
        return getClaims().get(PERSISTENT) == Boolean.TRUE;
    }

    /**
     * Set if the cookie must be persistent
     *
     * @param persistent if the cookie must be persistent
     */
    public void setPersistent(boolean persistent) {
        claimsBuilder.add(PERSISTENT, persistent);
    }

    /**
     * Get the name of the principal
     *
     * @return the name
     */
    @Override
    public String getName() {
        return getClaims().getSubject();
    }

    /**
     * Set the name of the principal
     *
     * @param name the name
     */
    public void setName(String name) {
        claimsBuilder.subject(name);
    }

}
