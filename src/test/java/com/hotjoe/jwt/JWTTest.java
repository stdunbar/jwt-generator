package com.hotjoe.jwt;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.UUID;

@QuarkusTest
public class JWTTest {

    @Inject
    JWTTokenUtil jwtTokenUtil;

    @Test
    public void testJWT() {

        String jwt = jwtTokenUtil.generateJWTToken("the subject");

        assert( jwtTokenUtil.isTokenValid(jwt) );
    }

    @Test
    public void testExpiredJWT() {
       String jwt = jwtTokenUtil.generateJWTToken(UUID.randomUUID().toString(), "https://www.blah.com/", 1, "user@example.com", "User", "Name" );

        System.out.println("sleeping 2 seconds to expire token...");
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        assert( !jwtTokenUtil.isTokenValid(jwt) );
    }

    @Test
    public void testJWTSig() {
        String jwt = jwtTokenUtil.generateJWTToken(UUID.randomUUID().toString(), "https://www.blah.com/", 60, "user@example.com", "User", "Name" );

        String[] jwtParts = jwt.split("\\.");

        String newJWT = jwtParts[0] + "." + jwtParts[1] + "." + UUID.randomUUID();

        assert( !jwtTokenUtil.isTokenValid(newJWT) );
    }
}
