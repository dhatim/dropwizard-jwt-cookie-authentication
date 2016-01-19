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
import java.security.Principal;
import java.util.Collection;
import java.util.Collections;
import java.util.Optional;

public class Subject implements Principal{
    
    private final static String LONG_TERM = "ltt"; // long-term token == rememberme
    private final static String ROLES = "rls";
    
    protected final Claims claims;

    public Subject(@JsonProperty("claims") Claims claims) {
        this.claims = claims;
    }

    public Claims getClaims() {
        return claims;
    }
    
    public boolean hasRole(String role){
        return getRoles().contains(role);
    }
    
    public Collection<String> getRoles(){
        return Optional.ofNullable(claims.get(ROLES))
                .map(Collection.class::cast)
                .orElse(Collections.emptyList());
    }
    
    public void setRoles(Collection<String> roles){
        claims.put(ROLES, roles);
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
