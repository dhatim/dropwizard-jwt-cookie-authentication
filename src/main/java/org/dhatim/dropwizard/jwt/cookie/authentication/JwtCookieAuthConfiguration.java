/**
 * Copyright 2020 Dhatim
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

import javax.annotation.Nullable;
import javax.validation.constraints.NotEmpty;

/**
 * Bundle configuration class
 */
public class JwtCookieAuthConfiguration {

    private String secretSeed;

    private boolean secure = false;

    private boolean httpOnly = true;

    @Nullable
    private SameSite sameSite = null;

    @NotEmpty
    private String sessionExpiryVolatile = "PT30m";

    @NotEmpty
    private String sessionExpiryPersistent = "P7d";

    /**
     * The secret seed use to generate the signing key.
     * It can be used to keep the same key value across application reboots.
     *
     * @return the signing key seed
     */
    public String getSecretSeed() {
        return secretSeed;
    }

    /**
     * Indicates if the 'secure' flag must be set on cookies
     *
     * @return if the 'secure' flag must be set on cookies
     */
    public boolean isSecure() {
        return secure;
    }

    /**
     * Indicates if the 'secure' flag must be set on cookies
     *
     * @return if the 'secure' flag must be set on cookies
     */
    public boolean isHttpOnly() {
        return httpOnly;
    }

    /**
     * duration of volatile cookies (in ISO 8601 format)
     *
     * @return the duration of volatile cookies
     */
    public String getSessionExpiryVolatile() {
        return sessionExpiryVolatile;
    }

    /**
     * duration of persistent cookies (in ISO 8601 format)
     *
     * @return the duration of persistent cookies
     */
    public String getSessionExpiryPersistent() {
        return sessionExpiryPersistent;
    }

    /**
     * {@code SameSite} cookie attribute value, as described <a href="https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#samesite-cookie-attribute">here</a>.
     *
     * @return {@code SameSite} cookie attribute value, or {@code null} if not set
     */
    public SameSite getSameSite() {
        return sameSite;
    }
}
