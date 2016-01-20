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

import org.hibernate.validator.constraints.NotEmpty;

/**
 * Bundle configuration class
 */
public class JwtCookieAuthConfiguration {
    
    private String secretSeed;
    
    private boolean httpsOnlyCookie = false;
    
    @NotEmpty
    private String sessionExpiryVolatile = "PT30m";
    
    @NotEmpty
    private String sessionExpiryPersistent = "P7d";

    /**
     * The secret seed use to generate the signing key.
     * It can be used to keep the same key value across application reboots.
     * @return the signing key seed
     */
    public String getSecretSeed() {
        return secretSeed;
    }

    /**
     * Indicates if the 'secure' flag must be set on cookies
     * @return if the 'secure' flag must be set on cookies
     */
    public boolean isHttpsOnlyCookie() {
        return httpsOnlyCookie;
    }

    /**
     * duration of volatile cookies (in ISO 8601 format)
     * @return the duration of volatile cookies
     */
    public String getSessionExpiryVolatile() {
        return sessionExpiryVolatile;
    }

    /**
     * duration of persistent cookies (in ISO 8601 format)
     * @return the duration of persistent cookies
     */
    public String getSessionExpiryPersistent() {
        return sessionExpiryPersistent;
    }
}
