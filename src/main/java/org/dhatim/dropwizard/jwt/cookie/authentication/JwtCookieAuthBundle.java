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
import io.dropwizard.auth.Authorizer;
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

/**
 * Dopwizard bundle
 * @param <C> Your application configuration class
 * @param <P> the class of the principal that will be serialized in / deserialized from JWT cookies
 */
public class JwtCookieAuthBundle<C extends Configuration, P extends JwtCookiePrincipal> implements ConfiguredBundle<C>{

    private final Class<P> principalType;
    private final Function<P,Claims> serializer;
    private final Function<Claims, P> deserializer;
    private Function<C, JwtCookieAuthConfiguration> configurationSupplier;
    private BiFunction<C, Environment, Key> keySuppplier;

    /**
     * Get a bundle instance that will use DefaultJwtCookiePrincipal
     * @param <C> Your application configuration class
     * @return a bundle instance that will use DefaultJwtCookiePrincipal
     */
    public static <C extends Configuration> JwtCookieAuthBundle<C, DefaultJwtCookiePrincipal> getDefault(){
        return new JwtCookieAuthBundle<>(
                DefaultJwtCookiePrincipal.class,
                DefaultJwtCookiePrincipal::getClaims,
                DefaultJwtCookiePrincipal::new);
    }
    
    /**
     * Build a new instance of JwtCookieAuthBundle
     * @param principalType the class of the principal that will be serialized in / deserialized from JWT cookies
     * @param serializer a function to serialize principals into JWT claims
     * @param deserializer a function to deserialize JWT claims into principals
     */
    public JwtCookieAuthBundle(Class<P> principalType, Function<P,Claims> serializer, Function<Claims, P> deserializer) {
        this.principalType = principalType;
        this.serializer = serializer;
        this.deserializer = deserializer;
        this.configurationSupplier = c -> new JwtCookieAuthConfiguration();
    }

    /**
     * If you want to sign the JWT with your own key, specify it here
     * @param keySupplier a bi-function which will return the signing key from the configuration and environment
     * @return this
     */
    public JwtCookieAuthBundle<C, P> withKeyProvider(BiFunction<C, Environment, Key> keySupplier){
        this.keySuppplier = keySupplier;
        return this;
    }

    /**
     * If you need to configure the bundle, specify it here
     * @param configurationSupplier a bi-function which will return the bundle configuration from the application configuration
     * @return this
     */
    public JwtCookieAuthBundle<C, P> withConfigurationSupplier(Function<C, JwtCookieAuthConfiguration> configurationSupplier) {
        this.configurationSupplier = configurationSupplier;
        return this;
    }
    
    
    @Override
    public void initialize(Bootstrap<?> bootstrap) {
        //in case somebody needs to serialize a DefaultJwtCookiePrincipal
        bootstrap.getObjectMapper().registerModule(new SimpleModule().addAbstractTypeMapping(Claims.class, DefaultClaims.class));
    }
    
    @Override
    public void run(C configuration, Environment environment) throws Exception {
        JwtCookieAuthConfiguration conf = configurationSupplier.apply(configuration);
        
        //build the key from the key factory if it was provided
        Key key = Optional
                .ofNullable(keySuppplier)
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
                .setPrefix("jwtCookie")
                .setAuthorizer((Authorizer<P>)(P::isInRole))
                .buildAuthFilter()));
        jerseyEnvironment.register(new AuthValueFactoryProvider.Binder<>(principalType));
        jerseyEnvironment.register(RolesAllowedDynamicFeature.class);
        
        jerseyEnvironment.register(new JwtCookieAuthResponseFilter<>(
                principalType,
                serializer,
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
