package com.hotjoe.services.user;

import com.auth0.jwt.exceptions.JWTCreationException;
import com.hotjoe.jwt.JWTTokenUtil;
import com.hotjoe.services.user.model.CreateTokenRequest;
import com.hotjoe.services.user.model.CreateTokenResponse;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import jakarta.annotation.PostConstruct;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;


@Path("/user")
public class UserTokenService {
    @Inject
    Logger logger;

    @Inject
    JWTTokenUtil jwtTokenUtil;

    @ConfigProperty(name="security.authorization.username")
    String userName;

    @ConfigProperty(name="security.authorization.password")
    String password;

    @PostConstruct
    protected void postConstruct() {
        if( (userName == null) || (password == null) ) {
            logger.error("username and/or password is not set.  Cannot continue!");

            throw new RuntimeException("username and/or password is not set.  Cannot continue!");
        }
    }


    @Path("/getToken")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response handleToken(CreateTokenRequest createTokenRequest) {
        CreateTokenResponse createTokenResponse = new CreateTokenResponse();

        if( createTokenRequest == null ) {
            createTokenResponse.setMessage(Response.Status.BAD_REQUEST.getReasonPhrase());

            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(createTokenResponse).build();
        }

        if( !userName.equals(createTokenRequest.getUserName()) || !password.equals(createTokenRequest.getPassword())) {
            createTokenResponse.setMessage(Response.Status.UNAUTHORIZED.getReasonPhrase());

            return Response.status(Response.Status.UNAUTHORIZED)
                     .entity(createTokenResponse).build();
        }

        try {
            createTokenResponse.setMessage(Response.Status.OK.getReasonPhrase());
            createTokenResponse.setToken(jwtTokenUtil.generateJWTToken(userName));

            return Response.ok(createTokenResponse).build();
        }
        catch (JWTCreationException exception) {
            logger.error("unable to create token: " + exception.getMessage());

            createTokenResponse.setMessage(Response.Status.INTERNAL_SERVER_ERROR.getReasonPhrase());

            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(createTokenResponse).build();
        }
    }
}
