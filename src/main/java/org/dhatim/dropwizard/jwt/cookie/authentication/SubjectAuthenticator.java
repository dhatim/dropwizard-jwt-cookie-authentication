package org.dhatim.dropwizard.jwt.cookie.authentication;

import com.google.common.base.Optional;
import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;
import java.security.Key;
import java.util.function.Function;

public class SubjectAuthenticator implements Authenticator<String, Subject> {

    private final Key key;
    private final Function<Claims, Subject> subjectFactory;

    public SubjectAuthenticator(Key key, Function<Claims, Subject> subjectFactory) {
        this.key = key;
        this.subjectFactory = subjectFactory;
    }

    @Override
    public Optional<Subject> authenticate(String credentials) throws AuthenticationException {
        try {
            return Optional.of(subjectFactory.apply(Jwts.parser().setSigningKey(key).parseClaimsJws(credentials).getBody()));
        } catch (ExpiredJwtException | SignatureException e) {
            return Optional.absent();
        }
    }

}
