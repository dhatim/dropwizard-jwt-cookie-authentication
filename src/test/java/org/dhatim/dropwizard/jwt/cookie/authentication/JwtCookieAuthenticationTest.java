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

import io.jsonwebtoken.lang.Strings;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.UUID;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import junit.framework.Assert;
import org.junit.ClassRule;
import org.junit.Test;

public class JwtCookieAuthenticationTest {

    @ClassRule
    public static final TestApplicationRule applicationRule = new TestApplicationRule();

    private final WebTarget target = ClientBuilder.newClient().target(applicationRule.baseUri()).path("principal");

    @Test
    public void testUnauthorized() {
        //calls to APIs with the @Auth annotation without prior authentication should result in HTTP 401
        Response response = target.request(MediaType.APPLICATION_JSON).get();
        Assert.assertEquals(401, response.getStatus());
    }

    @Test
    public void testCookieSetting() throws IOException {
        String principalName = UUID.randomUUID().toString();
        //a POST will set the principal
        Response response = target.request(MediaType.APPLICATION_JSON).post(Entity.json(new DefaultJwtCookiePrincipal(principalName)));
        Assert.assertEquals(200, response.getStatus());
        DefaultJwtCookiePrincipal principal = getPrincipal(response);
        Assert.assertEquals(principalName, principal.getName());

        //check that a session cookie has been set
        NewCookie cookie1 = response.getCookies().get("sessionToken");
        Assert.assertNotNull(cookie1);
        Assert.assertTrue(Strings.hasText(cookie1.getValue()));
        Assert.assertTrue(cookie1.isHttpOnly());

        //a GET with this cookie should return the Principal and refresh the cookie
        response = target.request(MediaType.APPLICATION_JSON).cookie(cookie1).get();
        Assert.assertEquals(200, response.getStatus());
        principal = getPrincipal(response);
        Assert.assertEquals(principalName, principal.getName());
        NewCookie cookie2 = response.getCookies().get("sessionToken");
        Assert.assertNotNull(cookie2);
        Assert.assertTrue(Strings.hasText(cookie1.getValue()));
        Assert.assertNotSame(cookie1.getValue(), cookie2.getValue());
    }

    @Test
    public void testDontRefreshSession() throws IOException{
        //requests made to methods annotated with @DontRefreshSession should not modify the cookie
        String principalName = UUID.randomUUID().toString();
        Response response = target.request(MediaType.APPLICATION_JSON).post(Entity.json(new DefaultJwtCookiePrincipal(principalName)));
        NewCookie cookie = response.getCookies().get("sessionToken");

        response = target.path("idempotent").request(MediaType.APPLICATION_JSON).cookie(cookie).get();
        Assert.assertEquals(200, response.getStatus());
        Assert.assertEquals(principalName, getPrincipal(response).getName());
        Assert.assertNull(response.getCookies().get("sessionToken"));
    }

    @Test
    public void testPublicEndpoint(){
        //public endpoints (i.e. not with @Auth, @RolesAllowed etc.) should not modify the cookie
        Response response = target.request(MediaType.APPLICATION_JSON).post(Entity.json(new DefaultJwtCookiePrincipal(UUID.randomUUID().toString())));
        NewCookie cookie = response.getCookies().get("sessionToken");

        //request made to public methods should not refresh the cookie
        response = target.path("public").request(MediaType.APPLICATION_JSON).cookie(cookie).get();
        Assert.assertEquals(200, response.getStatus());
        Assert.assertNull(response.getCookies().get("sessionToken"));
    }

    @Test
    public void testRememberMe() {
        //a volatile principal should set a volatile cookie
        DefaultJwtCookiePrincipal principal =  new DefaultJwtCookiePrincipal(UUID.randomUUID().toString());
        Response response = target.request(MediaType.APPLICATION_JSON).post(Entity.json(principal));
        NewCookie cookie = response.getCookies().get("sessionToken");
        Assert.assertNotNull(cookie);
        Assert.assertEquals(-1, cookie.getMaxAge());

        //a long term principal should set a persistent cookie
        principal.setPresistent(true);
        response = target.request(MediaType.APPLICATION_JSON).post(Entity.json(principal));
        cookie = response.getCookies().get("sessionToken");
        //default maxAge is 604800s (7 days)
        Assert.assertNotNull(cookie);
        Assert.assertEquals(604800, cookie.getMaxAge());
    }

    @Test
    public void testRoles() {
        WebTarget restrictedTarget = target.path("restricted");
        //try to access the resource without cookie (-> 401 UNAUTHORIZED)
        Response response = restrictedTarget.request().get();
        Assert.assertEquals(401, response.getStatus());

        //set a principal without the admin role (-> 403 FORBIDDEN)
        DefaultJwtCookiePrincipal principal = new DefaultJwtCookiePrincipal(UUID.randomUUID().toString());
        response = target.request(MediaType.APPLICATION_JSON).post(Entity.json(principal));
        NewCookie cookie = response.getCookies().get("sessionToken");
        Assert.assertNotNull(cookie);
        response = restrictedTarget.request().cookie(cookie).get();
        Assert.assertEquals(403, response.getStatus());

        //set a principal with the admin role (-> 200 OK)
        principal.setRoles(Collections.singleton("admin"));
        response = target.request(MediaType.APPLICATION_JSON).post(Entity.json(principal));
        cookie = response.getCookies().get("sessionToken");
        Assert.assertNotNull(cookie);
        response = restrictedTarget.request().cookie(cookie).get();
        Assert.assertEquals(200, response.getStatus());
    }

    @Test
    public void testDeleteCookie() {
        Response response = target.request(MediaType.APPLICATION_JSON).post(Entity.json(new DefaultJwtCookiePrincipal(UUID.randomUUID().toString())));
        NewCookie cookie = response.getCookies().get("sessionToken");
        Assert.assertNotNull(cookie);

        //removing the principal should produce a cookie with empty contenant and a past expiration date
        response = target.path("unset").request().cookie(cookie).get();
        Assert.assertEquals(204, response.getStatus());
        cookie = response.getCookies().get("sessionToken");
        Assert.assertNotNull(cookie);
        Assert.assertEquals("", cookie.getValue());
        Assert.assertEquals(Date.from(Instant.EPOCH), cookie.getExpiry());
    }

    private DefaultJwtCookiePrincipal getPrincipal(Response response) throws IOException {
        return applicationRule
                .getSupport()
                .getObjectMapper()
                .reader()
                .forType(DefaultJwtCookiePrincipal.class)
                .readValue(new InputStreamReader((InputStream) response.getEntity(), StandardCharsets.UTF_8));
    }

}
