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

import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SecurityException;

import java.security.Key;
import java.util.Optional;
import java.util.function.Function;

class JwtCookiePrincipalAuthenticator<P extends JwtCookiePrincipal> implements Authenticator<String, P> {

    private final Key key;
    private final Function<Claims, P> deserializer;

    public JwtCookiePrincipalAuthenticator(Key key, Function<Claims, P> deserializer) {
        this.key = key;
        this.deserializer = deserializer;
    }

    @Override
    public Optional<P> authenticate(String credentials) throws AuthenticationException {
        try {
            return Optional.of(deserializer.apply(Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(credentials).getBody()));
        } catch (ExpiredJwtException | SecurityException e) {
            return Optional.empty();
        }
    }

}
