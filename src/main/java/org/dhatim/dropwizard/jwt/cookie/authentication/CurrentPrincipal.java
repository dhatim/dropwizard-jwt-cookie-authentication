package org.dhatim.dropwizard.jwt.cookie.authentication;

import java.security.Principal;

public class CurrentPrincipal {

    private static final ThreadLocal<Principal> THREAD_LOCAL = new ThreadLocal<>();

    protected static void set(Principal principal){
        THREAD_LOCAL.set(principal);
    }

    protected static void remove(){
        THREAD_LOCAL.remove();
    }

    public static <P extends Principal> P get() {
        return (P)THREAD_LOCAL.get();
    }
}
