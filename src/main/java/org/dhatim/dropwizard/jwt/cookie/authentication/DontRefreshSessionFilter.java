package org.dhatim.dropwizard.jwt.cookie.authentication;

import java.io.IOException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;

@DontRefreshSession
public class DontRefreshSessionFilter implements ContainerRequestFilter{

    public static String DONT_REFRESH_SESSION_PROPERTY = "dontRefreshSession";
    
    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        requestContext.setProperty(DONT_REFRESH_SESSION_PROPERTY, Boolean.TRUE);
    }
    
}
