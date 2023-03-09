/**
 * Copyright 2023 Dhatim
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

import io.dropwizard.auth.AuthFilter;
import io.dropwizard.auth.AuthenticationException;
import java.io.IOException;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Priority;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Cookie;

@Priority(Priorities.AUTHENTICATION)
class JwtCookieAuthRequestFilter<P extends JwtCookiePrincipal> extends AuthFilter<String, P> {

    private final String cookieName;

    private JwtCookieAuthRequestFilter(String cookieName) {
        this.cookieName = cookieName;
    }

    @Override
    public void filter(ContainerRequestContext crc) throws IOException {
        Cookie cookie = crc.getCookies().get(cookieName);
        if (null != cookie) {
            String accessToken = cookie.getValue();
            if (accessToken != null && accessToken.length() > 0) {
                try {
                    final Optional<P> subject = authenticator.authenticate(accessToken);
                    if (subject.isPresent()) {
                        CurrentPrincipal.set(subject.get());
                        crc.setSecurityContext(new JwtCookieSecurityContext(subject.get(), crc.getSecurityContext().isSecure()));
                        return;
                    }
                } catch (AuthenticationException e) {
                    throw new InternalServerErrorException(e);
                }
            }
        }
        throw unauthorizedHandler.buildException(prefix, realm);
    }

    public static class Builder<P extends JwtCookiePrincipal> extends AuthFilterBuilder<String, P, JwtCookieAuthRequestFilter<P>> {

        private String cookieName;

        public Builder setCookieName(String cookieName) {
            this.cookieName = cookieName;
            return this;
        }

        @Override
        protected  JwtCookieAuthRequestFilter<P> newInstance() {
            return new JwtCookieAuthRequestFilter(Objects.requireNonNull(cookieName, "cookieName is not set"));
        }
    }
}