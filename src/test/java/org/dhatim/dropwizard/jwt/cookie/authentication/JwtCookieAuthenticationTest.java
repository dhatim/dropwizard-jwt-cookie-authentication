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

import io.jsonwebtoken.Jwts;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
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

    private final WebTarget target = ClientBuilder.newClient().target(applicationRule.baseUri()).path("subject");

    @Test
    public void testUnauthorized() {
        //calls to APIs with the @Auth annotation without prior authentication should result in HTTP 401
        Response response = target.request(MediaType.APPLICATION_JSON).get();
        Assert.assertEquals(401, response.getStatus());
    }

    @Test
    public void testCookieRefresh() throws IOException {
        String subjectName = UUID.randomUUID().toString();
        //a POST will set the subject
        Response response = target.request(MediaType.APPLICATION_JSON).post(Entity.json(new DefaultJwtCookiePrincipal(subjectName)));
        Assert.assertEquals(200, response.getStatus());
        DefaultJwtCookiePrincipal subject = getSubject(response);
        Assert.assertEquals(subjectName, subject.getName());

        //check that a session cookie has been set
        NewCookie cookie1 = response.getCookies().get("sessionToken");
        Assert.assertNotNull(cookie1);
        Assert.assertEquals(-1, cookie1.getMaxAge());

        //a GET with this cookie should send the DefaultJwtCookiePrincipal and refresh the cookie
        response = target.request(MediaType.APPLICATION_JSON).cookie(cookie1).get();
        Assert.assertEquals(200, response.getStatus());
        subject = getSubject(response);
        Assert.assertEquals(subjectName, subject.getName());
        NewCookie cookie2 = response.getCookies().get("sessionToken");
        Assert.assertNotNull(cookie2);
        Assert.assertNotSame(cookie1.getValue(), cookie2.getValue());

        //requests made to methods annotated with @DontRefreshSession should not refresh the cookie
        response = target.path("idempotent").request(MediaType.APPLICATION_JSON).cookie(cookie2).get();
        Assert.assertEquals(200, response.getStatus());
        subject = getSubject(response);
        Assert.assertEquals(subjectName, subject.getName());
        Assert.assertNull(response.getCookies().get("sessionToken"));
    }

    @Test
    public void testRememberMe() {
        //a volatile subject should not set a volatile cookie
        Response response = target.request(MediaType.APPLICATION_JSON).post(
                Entity.json(new DefaultJwtCookiePrincipal(UUID.randomUUID().toString(), false, Collections.emptyList())));
        NewCookie cookie = response.getCookies().get("sessionToken");
        //default maxAge is 604800s (7 days)
        Assert.assertNotNull(cookie);
        Assert.assertEquals(-1, cookie.getMaxAge());

        //a long term subject should set a persistent cookie
        response = target.request(MediaType.APPLICATION_JSON).post(
                Entity.json(new DefaultJwtCookiePrincipal(UUID.randomUUID().toString(), true, Collections.emptyList())));
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

        //set a subject without the admin role (-> 403 FORBIDDEN)
        DefaultJwtCookiePrincipal subject = new DefaultJwtCookiePrincipal(UUID.randomUUID().toString());
        response = target.request(MediaType.APPLICATION_JSON).post(Entity.json(subject));
        NewCookie cookie = response.getCookies().get("sessionToken");
        Assert.assertNotNull(cookie);
        response = restrictedTarget.request().cookie(cookie).get();
        Assert.assertEquals(403, response.getStatus());

        //set a subject with the admin role (-> 200 OK)
        subject.setRoles(Collections.singleton("admin"));
        response = target.request(MediaType.APPLICATION_JSON).post(Entity.json(subject));
        cookie = response.getCookies().get("sessionToken");
        Assert.assertNotNull(cookie);
        response = restrictedTarget.request().cookie(cookie).get();
        Assert.assertEquals(200, response.getStatus());

    }

    private DefaultJwtCookiePrincipal getSubject(Response response) throws IOException {
        return applicationRule
                .getSupport()
                .getObjectMapper()
                .reader()
                .forType(DefaultJwtCookiePrincipal.class)
                .readValue(new InputStreamReader((InputStream) response.getEntity(), StandardCharsets.UTF_8));
    }

}
