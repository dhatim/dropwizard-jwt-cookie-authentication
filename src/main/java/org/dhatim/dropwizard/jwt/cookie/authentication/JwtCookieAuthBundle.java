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

import com.fasterxml.jackson.databind.module.SimpleModule;
import com.google.common.hash.Hashing;
import com.google.common.primitives.Ints;
import io.dropwizard.auth.*;
import io.dropwizard.core.Configuration;
import io.dropwizard.core.ConfiguredBundle;
import io.dropwizard.core.setup.Bootstrap;
import io.dropwizard.core.setup.Environment;
import io.dropwizard.jersey.setup.JerseyEnvironment;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultClaims;
import jakarta.ws.rs.container.ContainerResponseFilter;
import org.glassfish.jersey.server.filter.RolesAllowedDynamicFeature;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * Dopwizard bundle
 *
 * @param <C> Your application configuration class
 * @param <P> the class of the principal that will be serialized in / deserialized from JWT cookies
 */
public class JwtCookieAuthBundle<C extends Configuration, P extends JwtCookiePrincipal> implements ConfiguredBundle<C> {

    public static final String JWT_COOKIE_DEFAULT_NAME = "sessionToken";
    private static final String JWT_COOKIE_PREFIX = "jwtCookie";

    private final Class<P> principalType;
    private final Function<P, Claims> serializer;
    private final Function<Claims, P> deserializer;
    private Function<C, JwtCookieAuthConfiguration> configurationSupplier;
    private BiFunction<C, Environment, Key> keySuppplier;
    private UnauthorizedHandler unauthorizedHandler;

    /**
     * Get a bundle instance that will use DefaultJwtCookiePrincipal
     *
     * @param <C> Your application configuration class
     * @return a bundle instance that will use DefaultJwtCookiePrincipal
     */
    public static <C extends Configuration> JwtCookieAuthBundle<C, DefaultJwtCookiePrincipal> getDefault() {
        return new JwtCookieAuthBundle<>(
                DefaultJwtCookiePrincipal.class,
                DefaultJwtCookiePrincipal::getClaims,
                DefaultJwtCookiePrincipal::new);
    }

    /**
     * Build a new instance of JwtCookieAuthBundle
     *
     * @param principalType the class of the principal that will be serialized in / deserialized from JWT cookies
     * @param serializer    a function to serialize principals into JWT claims
     * @param deserializer  a function to deserialize JWT claims into principals
     */
    public JwtCookieAuthBundle(Class<P> principalType, Function<P, Claims> serializer, Function<Claims, P> deserializer) {
        this.principalType = principalType;
        this.serializer = serializer;
        this.deserializer = deserializer;
        this.configurationSupplier = c -> new JwtCookieAuthConfiguration();
        this.unauthorizedHandler = new DefaultUnauthorizedHandler();
    }

    /**
     * If you want to sign the JWT with your own key, specify it here
     *
     * @param keySupplier a bi-function which will return the signing key from the configuration and environment
     * @return this
     */
    public JwtCookieAuthBundle<C, P> withKeyProvider(BiFunction<C, Environment, Key> keySupplier) {
        this.keySuppplier = keySupplier;
        return this;
    }

    /**
     * If you need to configure the bundle, specify it here
     *
     * @param configurationSupplier a bi-function which will return the bundle configuration from the application configuration
     * @return this
     */
    public JwtCookieAuthBundle<C, P> withConfigurationSupplier(Function<C, JwtCookieAuthConfiguration> configurationSupplier) {
        this.configurationSupplier = configurationSupplier;
        return this;
    }

    /**
     * If you want to use a different unauthorized handler, specify it here
     *
     * @param unauthorizedHandler an UnauthorizedHandler that will be used whenever a request fails to authenticate
     * @return this
     */
    public JwtCookieAuthBundle<C, P> withUnauthorizedHandler(UnauthorizedHandler unauthorizedHandler) {
        this.unauthorizedHandler = unauthorizedHandler;
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
                .orElseGet(() -> generateKey(conf.getSecretSeed()));

        JerseyEnvironment jerseyEnvironment = environment.jersey();
        jerseyEnvironment.register(new AuthDynamicFeature(getAuthRequestFilter(key, conf.getCookieName())));
        jerseyEnvironment.register(new AuthValueFactoryProvider.Binder<>(principalType));
        jerseyEnvironment.register(RolesAllowedDynamicFeature.class);
        jerseyEnvironment.register(getAuthResponseFilter(key, conf));
        jerseyEnvironment.register(DontRefreshSessionFilter.class);
    }

    /**
     * Get a filter that will deserialize the principal from JWT cookies found in HTTP requests
     *
     * @param key        the key used to validate the JWT
     * @param cookieName the name of the cookie holding the JWT
     * @return the request filter
     */
    public AuthFilter<String, P> getAuthRequestFilter(Key key, String cookieName) {
        return new JwtCookieAuthRequestFilter.Builder()
                .setCookieName(cookieName)
                .setAuthenticator(new JwtCookiePrincipalAuthenticator(key, deserializer))
                .setPrefix(JWT_COOKIE_PREFIX)
                .setAuthorizer((Authorizer<P>) (principal, role, requestContext) -> principal.isInRole(role))
                .setUnauthorizedHandler(unauthorizedHandler)
                .buildAuthFilter();
    }

    /**
     * Get a filter that will deserialize the principal from JWT cookies found in HTTP requests,
     * using the default cookie name.
     *
     * @param key the key used to validate the JWT
     * @return the request filter
     */
    public AuthFilter<String, P> getAuthRequestFilter(Key key) {
        return getAuthRequestFilter(key, JWT_COOKIE_DEFAULT_NAME);
    }

    /**
     * Get a filter that will serialize principals into JWTs and add them to HTTP response cookies
     *
     * @param key           the key used to sign the JWT
     * @param configuration cookie configuration (secure, httpOnly, expiration...)
     * @return the response filter
     */
    public ContainerResponseFilter getAuthResponseFilter(Key key, JwtCookieAuthConfiguration configuration) {
        return new JwtCookieAuthResponseFilter<>(
                principalType,
                serializer,
                configuration.getCookieName(),
                configuration.isSecure(),
                configuration.isHttpOnly(),
                configuration.getDomain(),
                configuration.getSameSite(),
                key,
                Ints.checkedCast(Duration.parse(configuration.getSessionExpiryVolatile()).getSeconds()),
                Ints.checkedCast(Duration.parse(configuration.getSessionExpiryPersistent()).getSeconds()));
    }

    /**
     * Generate a HMAC SHA256 Key that can be used to sign JWTs
     *
     * @param secretSeed a seed from which the key will be generated.
     *                   Identical seeds will generate identical keys.
     *                   If null, a random key is returned.
     * @return a HMAC SHA256 Key
     */
    public static Key generateKey(String secretSeed) {
        // make a key from the seed if it was provided
        return Optional.ofNullable(secretSeed)
                .map(seed -> Hashing.sha256().newHasher().putString(seed, StandardCharsets.UTF_8).hash().asBytes())
                .map(k -> (Key) new SecretKeySpec(k, SignatureAlgorithm.HS256.getJcaName()))
                //else generate a random key
                .orElseGet(getHmacSha256KeyGenerator()::generateKey);
    }

    private static KeyGenerator getHmacSha256KeyGenerator() {
        try {
            return KeyGenerator.getInstance(SignatureAlgorithm.HS256.getJcaName());
        } catch (NoSuchAlgorithmException e) {
            throw new SecurityException(e);
        }
    }
}
