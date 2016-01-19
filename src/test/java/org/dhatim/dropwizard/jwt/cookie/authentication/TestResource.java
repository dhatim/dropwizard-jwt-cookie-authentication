package com.example.trying;

import io.dropwizard.auth.Auth;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import org.dhatim.dropwizard.jwt.cookie.authentication.DontRefreshSession;
import org.dhatim.dropwizard.jwt.cookie.authentication.JwtCookieSecurityContext;
import org.dhatim.dropwizard.jwt.cookie.authentication.Subject;

@Path("subject")
public class TestResource {
    
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Subject setSubject(@Context ContainerRequestContext requestContext, Subject subject){
        requestContext.setSecurityContext(new JwtCookieSecurityContext(subject, requestContext.getSecurityContext().isSecure()));
        return subject;
    }
    
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Subject getSubject(@Auth Subject subject){
        return subject;
    }
    
    @GET
    @Path("idempotent")
    @Produces(MediaType.APPLICATION_JSON)
    @DontRefreshSession
    public Subject getSubjectWithoutRefreshingSession(@Auth Subject subject){
        return subject;
    }
    
}
