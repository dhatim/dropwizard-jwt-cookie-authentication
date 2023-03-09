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

import io.dropwizard.Configuration;
import io.dropwizard.testing.junit5.DropwizardAppExtension;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import io.jsonwebtoken.lang.Strings;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.UUID;

@ExtendWith(DropwizardExtensionsSupport.class)
public class JwtCookieAuthenticationTest {

    private static final DropwizardAppExtension<Configuration> EXT = new DropwizardAppExtension<Configuration>(TestApplication.class);
    private static final String COOKIE_NAME = "sessionToken";

    private WebTarget getTarget() {
        return EXT.client().target("http://localhost:" + EXT.getLocalPort() + "/application").path("principal");
    }

    @Test
    public void testUnauthorized() {
        //calls to APIs with the @Auth annotation without prior authentication should result in HTTP 401
        Response response = getTarget().request(MediaType.APPLICATION_JSON).get();
        Assertions.assertEquals(401, response.getStatus());
    }

    @Test
    public void testCookieSetting() throws IOException {
        String principalName = UUID.randomUUID().toString();
        //a POST will set the principal
        Response response = getTarget().request(MediaType.APPLICATION_JSON).post(Entity.json(new DefaultJwtCookiePrincipal(principalName)));
        Assertions.assertEquals(200, response.getStatus());
        DefaultJwtCookiePrincipal principal = getPrincipal(response);
        Assertions.assertEquals(principalName, principal.getName());

        //check that a session cookie has been set
        NewCookie cookie1 = response.getCookies().get(COOKIE_NAME);
        Assertions.assertNotNull(cookie1);
        Assertions.assertTrue(Strings.hasText(cookie1.getValue()));
        Assertions.assertTrue(cookie1.isHttpOnly());

        //a GET with this cookie should return the Principal and refresh the cookie
        response = getTarget().request(MediaType.APPLICATION_JSON).cookie(cookie1).get();
        Assertions.assertEquals(200, response.getStatus());
        principal = getPrincipal(response);
        Assertions.assertEquals(principalName, principal.getName());
        NewCookie cookie2 = response.getCookies().get(COOKIE_NAME);
        Assertions.assertNotNull(cookie2);
        Assertions.assertTrue(Strings.hasText(cookie1.getValue()));
        Assertions.assertNotSame(cookie1.getValue(), cookie2.getValue());
    }

    @Test
    public void testDontRefreshSession() throws IOException {
        //requests made to methods annotated with @DontRefreshSession should not modify the cookie
        String principalName = UUID.randomUUID().toString();
        Response response = getTarget().request(MediaType.APPLICATION_JSON).post(Entity.json(new DefaultJwtCookiePrincipal(principalName)));
        NewCookie cookie = response.getCookies().get(COOKIE_NAME);

        response = getTarget().path("idempotent").request(MediaType.APPLICATION_JSON).cookie(cookie).get();
        Assertions.assertEquals(200, response.getStatus());
        Assertions.assertEquals(principalName, getPrincipal(response).getName());
        Assertions.assertNull(response.getCookies().get(COOKIE_NAME));
    }

    @Test
    public void testPublicEndpoint() {
        //public endpoints (i.e. not with @Auth, @RolesAllowed etc.) should not modify the cookie
        Response response = getTarget().request(MediaType.APPLICATION_JSON).post(Entity.json(new DefaultJwtCookiePrincipal(UUID.randomUUID().toString())));
        NewCookie cookie = response.getCookies().get(COOKIE_NAME);

        //request made to public methods should not refresh the cookie
        response = getTarget().path("public").request(MediaType.APPLICATION_JSON).cookie(cookie).get();
        Assertions.assertEquals(200, response.getStatus());
        Assertions.assertNull(response.getCookies().get(COOKIE_NAME));
    }

    @Test
    public void testRememberMe() {
        //a volatile principal should set a volatile cookie
        DefaultJwtCookiePrincipal principal = new DefaultJwtCookiePrincipal(UUID.randomUUID().toString());
        Response response = getTarget().request(MediaType.APPLICATION_JSON).post(Entity.json(principal));
        NewCookie cookie = response.getCookies().get(COOKIE_NAME);
        Assertions.assertNotNull(cookie);
        Assertions.assertEquals(-1, cookie.getMaxAge());

        //a long term principal should set a persistent cookie
        principal.setPersistent(true);
        response = getTarget().request(MediaType.APPLICATION_JSON).post(Entity.json(principal));
        cookie = response.getCookies().get(COOKIE_NAME);
        //default maxAge is 604800s (7 days)
        Assertions.assertNotNull(cookie);
        Assertions.assertEquals(604800, cookie.getMaxAge());
    }

    @Test
    public void testRoles() {
        WebTarget restrictedTarget = getTarget().path("restricted");
        //try to access the resource without cookie (-> 401 UNAUTHORIZED)
        Response response = restrictedTarget.request().get();
        Assertions.assertEquals(401, response.getStatus());

        //set a principal without the admin role (-> 403 FORBIDDEN)
        DefaultJwtCookiePrincipal principal = new DefaultJwtCookiePrincipal(UUID.randomUUID().toString());
        response = getTarget().request(MediaType.APPLICATION_JSON).post(Entity.json(principal));
        NewCookie cookie = response.getCookies().get(COOKIE_NAME);
        Assertions.assertNotNull(cookie);
        response = restrictedTarget.request().cookie(cookie).get();
        Assertions.assertEquals(403, response.getStatus());

        //set a principal with the admin role (-> 200 OK)
        principal.setRoles(Collections.singleton("admin"));
        response = getTarget().request(MediaType.APPLICATION_JSON).post(Entity.json(principal));
        cookie = response.getCookies().get(COOKIE_NAME);
        Assertions.assertNotNull(cookie);
        response = restrictedTarget.request().cookie(cookie).get();
        Assertions.assertEquals(200, response.getStatus());
    }

    @Test
    public void testDeleteCookie() {
        Response response = getTarget().request(MediaType.APPLICATION_JSON).post(Entity.json(new DefaultJwtCookiePrincipal(UUID.randomUUID().toString())));
        NewCookie cookie = response.getCookies().get(COOKIE_NAME);
        Assertions.assertNotNull(cookie);

        //removing the principal should produce a cookie with empty contenant and a past expiration date
        response = getTarget().path("unset").request().cookie(cookie).get();
        Assertions.assertEquals(204, response.getStatus());
        cookie = response.getCookies().get(COOKIE_NAME);
        Assertions.assertNotNull(cookie);
        Assertions.assertEquals("", cookie.getValue());
        Assertions.assertEquals(Date.from(Instant.EPOCH), cookie.getExpiry());
    }

    @Test
    public void testGetCurrentPrincipal() throws IOException {
        //test to get principal from CurrentPrincipal.get() instead of @Auth
        String principalName = UUID.randomUUID().toString();
        Response response = getTarget().request(MediaType.APPLICATION_JSON).post(Entity.json(new DefaultJwtCookiePrincipal(principalName)));
        NewCookie cookie = response.getCookies().get(COOKIE_NAME);
        Assertions.assertNotNull(cookie);

        response = getTarget().path("current").request(MediaType.APPLICATION_JSON).cookie(cookie).get();
        Assertions.assertEquals(200, response.getStatus());
        Assertions.assertEquals(principalName, getPrincipal(response).getName());
    }

    private DefaultJwtCookiePrincipal getPrincipal(Response response) throws IOException {
        return EXT.getObjectMapper()
                .reader()
                .forType(DefaultJwtCookiePrincipal.class)
                .readValue(new InputStreamReader((InputStream) response.getEntity(), StandardCharsets.UTF_8));
    }

}
