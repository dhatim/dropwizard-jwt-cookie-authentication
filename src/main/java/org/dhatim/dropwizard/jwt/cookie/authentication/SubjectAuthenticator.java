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

import com.google.common.base.Optional;
import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;
import java.security.Key;
import java.util.function.Function;

class SubjectAuthenticator implements Authenticator<String, Subject> {

    private final Key key;
    private final Function<Claims, Subject> subjectFactory;

    public SubjectAuthenticator(Key key, Function<Claims, Subject> subjectFactory) {
        this.key = key;
        this.subjectFactory = subjectFactory;
    }

    @Override
    public Optional<Subject> authenticate(String credentials) throws AuthenticationException {
        try {
            return Optional.of(subjectFactory.apply(Jwts.parser().setSigningKey(key).parseClaimsJws(credentials).getBody()));
        } catch (ExpiredJwtException | SignatureException e) {
            return Optional.absent();
        }
    }

}
