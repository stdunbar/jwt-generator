package com.hotjoe.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

/**
 * Manages JWT interactions.  This class generates and validates the JWT's using
 * the <a href="https://github.com/auth0/java-jwt">Auth0</a> library.
 * <br/>
 * To generate the public and private .pem files, start with:
 * <br />
 * <code>
 *     openssl genrsa -out private.rsa.pem 2048
 * </code>
 * <br />
 * This generates a 2048-bit RSA private key.  To generate a key that this code can use run:
 * <br />
 * <code>
 *     openssl pkcs8 -topk8 -inform PEM -in private.rsa.pem -out private.pkcs8 -nocrypt
 * </code>
 * <br />
 * To generate the public key keep use the original .pem file.  The public key can stat in RSA
 * format:
 * <br />
 * <code>
 *     openssl pkey -in private.rsa.pem -pubout -out public.pem
 * </code>
 * The pkcs8 file needs to be in the root of the classpath.  This code has been tested with
 * 2048 bit and 4096-bit keys.  Others are likely to work but have not been tested.
 */
@ApplicationScoped
public class JWTTokenUtil {
    @Inject
    Logger logger;

    @ConfigProperty(name = "security.jwt.default.secondsToExpiration", defaultValue = "3600")
    int defaultSecondsToExpiration;

    @ConfigProperty(name = "security.jwt.default.issuer", defaultValue = "https://www.hotjoe.com/")
    String defaultIssuer;

    String usedIssuer = null;


    /**
     * Generates a JWT token with most of the values defaulted.
     *
     * @param subject the "sub" of the JWT.  This is subject of the token and identifies the principal of the token.
     *                Note from <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.2"></a>RFC 7519</a> the
     *                subject MUST be "locally unique in the context of the issuer or be globally unique".  Commonly
     *                this is a GUID that is identifies the user.
     *
     * @return the JWT token as a String
     */
    public String generateJWTToken(String subject) {
        return generateJWTToken(subject, defaultIssuer, defaultSecondsToExpiration, null, null, null);
    }

    /**
     * Generates a JWT token with control over some of the values.
     *
     * @param subject the "sub" of the JWT.  This is subject of the token and identifies the principal of the token.
     *                Note from <a href="https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.2"></a>RFC 7519</a> the
     *                subject MUST be "locally unique in the context of the issuer or be globally unique".  Commonly
     *                this is a GUID that is identifies the user.
     * @param issuer the "iss" of the JWT.  Sometimes a website, sometimes a String.  Specifies who issued the token.
     * @param secondsToExpiration the TTL of the token, specified in seconds.
     * @param email the email of the user that the token is for.  This is placed in the "email" claim.
     * @param givenName the given (first) name of the user.  This is placed in the "given_name" claim.
     * @param familyName the family (last) name of the user.  This is placed in the "family_name" claim.
     *
     * @return the JWT token as a String
     */
    public String generateJWTToken(String subject,
                                   String issuer,
                                   int secondsToExpiration,
                                   String email,
                                   String givenName,
                                   String familyName) {
        Algorithm algorithm = Algorithm.RSA256(null, getPrivateKey());

        Date now = new Date();

        usedIssuer = issuer;

        JWTCreator.Builder builder = JWT.create()
                .withIssuer(issuer)
                .withSubject(subject)
                .withClaim("jti", UUID.randomUUID().toString())
                .withNotBefore(now)
                .withIssuedAt(now)
                .withExpiresAt(new Date(now.toInstant().plus(secondsToExpiration, ChronoUnit.SECONDS).toEpochMilli()));

        if (email != null)
            builder = builder.withClaim("email", email);
        if (givenName != null)
            builder = builder.withClaim("given_name", givenName);
        if (familyName != null)
            builder = builder.withClaim("family_name", familyName);

        return builder.sign(algorithm);
    }

    /**
     * Validates that a given JWT token string is valid.
     *
     * @param token the JWT as a String
     *
     * @return true if the token is valid, false otherwise
     */
    public boolean isTokenValid(String token) {
        try {
            validateToken(token);
        } catch (JWTVerificationException exception) {
            logger.info("token is not valid - reason: " + exception.getMessage());
            return false;
        }

        return true;
    }

    /**
     * Validates that a given JWT token string is valid.
     *
     * @param token the JWT as a String
     *
     * @return a DecodedJWT if the token is valid
     *
     * @throws JWTVerificationException if there is an error validating the token
     *
     */
    public DecodedJWT validateToken(String token) throws JWTVerificationException {
        if( token == null )
            throw new NullPointerException("token cannot be null");

        Algorithm algorithm = Algorithm.RSA256(getPublicKey(), null);
        JWTVerifier jwtVerifier = JWT.require(algorithm)
                .withIssuer(usedIssuer)
                .build();

        return jwtVerifier.verify(token);
    }
    /**
     * Helper method to read an RSAPublicKey from a .pem file.
     *
     * @return the RSAPublicKey or null if an error occurs
     */
    private RSAPublicKey getPublicKey() {
        try (InputStream inputStream = JWTTokenUtil.class.getResourceAsStream("/public.pem")) {
            if (inputStream == null) {
                logger.info("can't find public.pem in class path");
                return null;
            }

            String publicKeyPem = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
            publicKeyPem = publicKeyPem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replaceAll("\r", "")
                    .replaceAll("\n", "")
                    .replace("-----END PUBLIC KEY-----", "");
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyPem);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);

            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException ioe) {
            logger.error("Exception reading public key - " + ioe.getMessage());
            return null;
        }
    }

    /**
     * Helper method to read an RSAPrivateKey from a .pkcs8 file.
     *
     * @return the RSAPrivateKey or null if an error occurs
     */
    private RSAPrivateKey getPrivateKey() {
        try (InputStream inputStream = JWTTokenUtil.class.getResourceAsStream("/private.pkcs8")) {
            if (inputStream == null) {
                logger.error("can't find private.pkcs8 in class path");
                return null;
            }

            String privateKeyPem = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
            privateKeyPem = privateKeyPem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replaceAll("\r", "")
                    .replaceAll("\n", "")
                    .replace("-----END PRIVATE KEY-----", "");
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyPem);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);

        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException ioe) {
            logger.error("Exception reading private key - " + ioe.getMessage());
            return null;
        }
    }
}
