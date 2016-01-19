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
