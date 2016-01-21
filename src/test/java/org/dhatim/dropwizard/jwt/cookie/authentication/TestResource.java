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

import io.dropwizard.auth.Auth;
import javax.annotation.security.RolesAllowed;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

@Path("principal")
public class TestResource {
    
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public DefaultJwtCookiePrincipal setPrincipal(@Context ContainerRequestContext requestContext, DefaultJwtCookiePrincipal principal){
        requestContext.setSecurityContext(new JwtCookieSecurityContext(principal, requestContext.getSecurityContext().isSecure()));
        return principal;
    }
    
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public DefaultJwtCookiePrincipal getPrincipal(@Auth DefaultJwtCookiePrincipal principal){
        return principal;
    }
    
    @GET
    @Path("idempotent")
    @Produces(MediaType.APPLICATION_JSON)
    @DontRefreshSession
    public DefaultJwtCookiePrincipal getPrincipalWithoutRefreshingSession(@Auth DefaultJwtCookiePrincipal principal){
        return principal;
    }
    
    @GET
    @Path("restricted")
    @RolesAllowed("admin")
    public String getRestrictedResource(){
        return "SuperSecretStuff";
    }
    
}
