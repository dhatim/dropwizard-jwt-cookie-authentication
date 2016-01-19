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

import com.fasterxml.jackson.databind.module.SimpleModule;
import com.google.common.hash.Hashing;
import com.google.common.primitives.Ints;
import io.dropwizard.Configuration;
import io.dropwizard.ConfiguredBundle;
import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.jersey.setup.JerseyEnvironment;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.impl.DefaultClaims;
import java.nio.charset.StandardCharsets;
import java.util.function.Function;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Optional;
import java.util.function.BiFunction;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import org.glassfish.jersey.server.filter.RolesAllowedDynamicFeature;


public class JwtCookieAuthBundle<T extends Configuration> implements ConfiguredBundle<T>{

    private final Function<T, JwtCookieAuthConfiguration> jwtCookieAuthConfigurationExtractor;
    private Function<Claims, Subject> subjectFactory;
    private BiFunction<T, Environment, Key> keyFactory;

    public JwtCookieAuthBundle(Function<T, JwtCookieAuthConfiguration> jwtCookieAuthConfigurationExtractor) {
        this.jwtCookieAuthConfigurationExtractor = jwtCookieAuthConfigurationExtractor;
        this.subjectFactory = Subject::new;
    }

    public JwtCookieAuthBundle<T> setSubjectFactory(Function<Claims, Subject> subjectFactory){
        this.subjectFactory = subjectFactory;
        return this;
    }
    
    public JwtCookieAuthBundle<T> setKeyFactory(BiFunction<T, Environment, Key> keyFactory){
        this.keyFactory = keyFactory;
        return this;
    }

    @Override
    public void initialize(Bootstrap<?> bootstrap) {
        //in case somebody needs to serialize a Subject
        bootstrap.getObjectMapper().registerModule(new SimpleModule().addAbstractTypeMapping(Claims.class, DefaultClaims.class));
    }
    
    @Override
    public void run(T configuration, Environment environment) throws Exception {
        JwtCookieAuthConfiguration conf = jwtCookieAuthConfigurationExtractor.apply(configuration);
        
        //build the key from the key factory if it was provided
        Key key = Optional
                .ofNullable(keyFactory)
                .map(k -> k.apply(configuration, environment))
                .orElseGet(() -> 
                    //else make a key from the seed if it was provided
                    Optional.ofNullable(conf.getSecretSeed())
                            .map(seed -> Hashing.sha256().newHasher().putString(seed, StandardCharsets.UTF_8).hash().asBytes())
                            .map(k -> (Key) new SecretKeySpec(k, "HmacSHA256"))
                            //else generate a random key
                            .orElseGet(getHmacSha256KeyGenerator()::generateKey)
                );
        
        JerseyEnvironment jerseyEnvironment = environment.jersey();
        
        String cookieName = "sessionToken";
        jerseyEnvironment.register(new AuthDynamicFeature(
                new JwtCookieAuthRequestFilter.Builder()
                .setCookieName(cookieName)
                .setAuthenticator(new SubjectAuthenticator(key, subjectFactory))
                .setAuthorizer(Subject::hasRole)
                .buildAuthFilter()));
        jerseyEnvironment.register(new AuthValueFactoryProvider.Binder<>(Subject.class));
        jerseyEnvironment.register(RolesAllowedDynamicFeature.class);
        
        jerseyEnvironment.register(new JwtCookieAuthResponseFilter(
                cookieName,
                conf.isHttpsOnlyCookie(),
                key,
                Ints.checkedCast(Duration.parse(conf.getSessionExpiryVolatile()).getSeconds()),
                Ints.checkedCast(Duration.parse(conf.getSessionExpiryPersistent()).getSeconds())));
        
        jerseyEnvironment.register(DontRefreshSessionFilter.class);
    }

    private static KeyGenerator getHmacSha256KeyGenerator(){
        try{
            return KeyGenerator.getInstance("HmacSHA256");
        } catch(NoSuchAlgorithmException e){
            throw new SecurityException(e);
        }
    }
}
