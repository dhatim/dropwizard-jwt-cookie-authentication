package org.dhatim.dropwizard.jwt.cookie.authentication;

public enum SameSite {

    NONE("None"), LAX("Lax"), STRICT("Strict");

    public final String value;

    SameSite(String value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return value;
    }
}
