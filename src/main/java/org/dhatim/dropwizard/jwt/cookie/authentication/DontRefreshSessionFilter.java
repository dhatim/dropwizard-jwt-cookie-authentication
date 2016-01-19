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

import java.io.IOException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;

@DontRefreshSession
class DontRefreshSessionFilter implements ContainerRequestFilter{

    public static String DONT_REFRESH_SESSION_PROPERTY = "dontRefreshSession";
    
    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        requestContext.setProperty(DONT_REFRESH_SESSION_PROPERTY, Boolean.TRUE);
    }
    
}
