package org.dhatim.dropwizard.jwt.cookie.authentication;

import java.lang.annotation.Retention;
import java.lang.annotation.ElementType;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import javax.ws.rs.NameBinding;

/**
 * An annotation that can be used to avoid reseting the session TTL when an API is called
 */
@NameBinding
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface DontRefreshSession {
    
}
