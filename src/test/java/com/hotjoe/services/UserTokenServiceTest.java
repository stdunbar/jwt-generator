package com.hotjoe.services;

import com.fasterxml.jackson.databind.util.JSONPObject;
import com.hotjoe.services.user.model.CreateTokenRequest;
import com.hotjoe.services.user.model.ValidateTokenRequest;
import com.hotjoe.services.user.model.ValidateTokenResponse;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import io.restassured.specification.RequestSpecification;
import org.junit.jupiter.api.Test;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.notNullValue;

@QuarkusTest
public class UserTokenServiceTest {

    @Test
    public void testSuccessfulAuth() {
        CreateTokenRequest createTokenRequest = new CreateTokenRequest();
        createTokenRequest.setUserName("tommy");
        createTokenRequest.setPassword("tutone");

        given()
                .contentType(MediaType.APPLICATION_JSON)
                .body(createTokenRequest)
          .when()
                .post("/user/getToken")
          .then()
             .statusCode(Response.Status.OK.getStatusCode())
             .body(
                     "message", is(Response.Status.OK.getReasonPhrase()),
                     "token", notNullValue()
             );
    }

    @Test
    public void testUnsuccessfulAuth() {
        CreateTokenRequest createTokenRequest = new CreateTokenRequest();
        createTokenRequest.setUserName("tommy");
        createTokenRequest.setPassword("blah");

        given()
                .contentType(MediaType.APPLICATION_JSON)
                .body(createTokenRequest)
            .when()
                .post("/user/getToken")
            .then()
                .statusCode(Response.Status.UNAUTHORIZED.getStatusCode())
                .body(
                        "message", is(Response.Status.UNAUTHORIZED.getReasonPhrase()),
                        "$", not(hasKey("token"))
                );
    }

    @Test
    public void testBadContentType() {
        given()
                .contentType(MediaType.TEXT_PLAIN)
                .body("blah blah")
            .when()
                .post("/user/getToken")
            .then()
                .statusCode(Response.Status.UNSUPPORTED_MEDIA_TYPE.getStatusCode());
    }

    @Test
    public void testEmptyBody() {
        given()
                .contentType(MediaType.APPLICATION_JSON)
            .when()
                .post("/user/getToken")
             .then()
                .statusCode(Response.Status.BAD_REQUEST.getStatusCode())
                .body(
                        "message", is(Response.Status.BAD_REQUEST.getReasonPhrase()),
                        "$", not(hasKey("token"))
                );
    }

    @Test
    public void testMissingParameter() {
        CreateTokenRequest createTokenRequest = new CreateTokenRequest();
        createTokenRequest.setUserName("tommy");

        given()
                .contentType(MediaType.APPLICATION_JSON)
                .body(createTokenRequest)
            .when()
                .post("/user/getToken")
            .then()
                .statusCode(Response.Status.UNAUTHORIZED.getStatusCode())
                .body(
                        "message", is(Response.Status.UNAUTHORIZED.getReasonPhrase()),
                        "$", not(hasKey("token"))
                );
    }

    @Test
    public void testSuccessfulAuthWithValidate() {
        CreateTokenRequest createTokenRequest = new CreateTokenRequest();
        createTokenRequest.setUserName("tommy");
        createTokenRequest.setPassword("tutone");

        String token = given()
                .contentType(MediaType.APPLICATION_JSON)
                .body(createTokenRequest)
            .when()
                .post("/user/getToken")
            .then()
                .statusCode(Response.Status.OK.getStatusCode())
                .extract().body().path("token");

        ValidateTokenRequest validateTokenRequest = new ValidateTokenRequest();
        validateTokenRequest.setToken(token);

        given()
                .contentType(MediaType.APPLICATION_JSON)
                .body(validateTokenRequest)
            .when()
                .post("/user/validateToken")
            .then()
                .statusCode(Response.Status.OK.getStatusCode());
    }

    @Test
    public void testSuccessfulAuthWithMungedTokenValidate() {
        CreateTokenRequest createTokenRequest = new CreateTokenRequest();
        createTokenRequest.setUserName("tommy");
        createTokenRequest.setPassword("tutone");

        String token = given()
                .contentType(MediaType.APPLICATION_JSON)
                .body(createTokenRequest)
                .when()
                .post("/user/getToken")
                .then()
                .statusCode(Response.Status.OK.getStatusCode())
                .extract().body().path("token");

        //
        // munge the token a bit
        //
        token = token.substring(0, token.length() - 4) + "abcd";

        ValidateTokenRequest validateTokenRequest = new ValidateTokenRequest();
        validateTokenRequest.setToken(token);

        given()
                .contentType(MediaType.APPLICATION_JSON)
                .body(validateTokenRequest)
                .when()
                .post("/user/validateToken")
                .then()
                .statusCode(Response.Status.BAD_REQUEST.getStatusCode());
    }
}
