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

import com.fasterxml.jackson.annotation.JsonProperty;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import java.util.Collection;
import java.util.Collections;
import java.util.Optional;

/**
 * Default implementation of JwtCookiePrincipal
 */
public class DefaultJwtCookiePrincipal implements JwtCookiePrincipal{
    
    private final static String PERSISTENT = "pst"; // long-term token == rememberme
    private final static String ROLES = "rls";
    
    protected final Claims claims;

    /**
     * Builds a new instance of DefaultJwtCookiePrincipal
     * @param name the principal name
     * @param persistent if the cookie must be persistent
     * @param roles the roles the princiapl is in
     */
    public DefaultJwtCookiePrincipal(@JsonProperty("name")String name, @JsonProperty("persistent")boolean persistent, @JsonProperty("roles")Collection<String> roles, @JsonProperty("claims")Claims claims){
        this.claims = Optional.ofNullable(claims).orElseGet(Jwts::claims);
        this.claims.setSubject(name);
        this.claims.put(PERSISTENT, persistent);
        this.claims.put(ROLES, roles);
    }
    
    /**
     * Build a new instance of DefaultJwtCookiePrincipal with the given name
     * @param name the name
     */
    public DefaultJwtCookiePrincipal(String name){
        this(name, false, Collections.emptyList(), null);
    }
    
    /**
     * Build a new instance of DefaultJwtCookiePrincipal from the JWT claims
     * @param claims the JWT claims
     */
    public DefaultJwtCookiePrincipal(@JsonProperty("claims") Claims claims) {
        this.claims = claims;
    }

    /**
     * Get the claims used to serialize this principal
     * @return the claims
     */
    public Claims getClaims() {
        return claims;
    }
    
    /**
    * Indicates if this principal has the given role
    * @param role the role
    * @return true if the principal is in the given role, false otherwise
    */
    @Override
    public boolean hasRole(String role){
        return getRoles().contains(role);
    }
    
    /**
     * Get a collection of all the roles this principal is in
     * @return the roles
     */
    public Collection<String> getRoles(){
        return Optional.ofNullable(claims.get(ROLES))
                .map(Collection.class::cast)
                .orElse(Collections.emptyList());
    }
    
    /**
     * Set the roles this principal is in
     * @param roles the roles
     */
    public void setRoles(Collection<String> roles){
        claims.put(ROLES, roles);
    }
    
    /**
     * Indicates if the cookie must be persistent
     * @return if the cookie must be persistent
     */
    @Override
    public boolean isPersistent() {
        return claims.get(PERSISTENT) == Boolean.TRUE;
    }
    
    /**
     * Set if the cookie must be persistent
     * @param persistent if the cookie must be persistent
     */
    public void setPresistent(boolean persistent){
        claims.put(PERSISTENT, persistent);
    }

    /**
     * Get the name of the principal
     * @return the name
     */
    @Override
    public String getName() {
        return (String) claims.getSubject();
    }
    
    /**
     * Set the name of the principal
     * @param name the name
     */
    public void setName(String name) {
        claims.setSubject(name);
    }
    
}
