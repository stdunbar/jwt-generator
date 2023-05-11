package com.hotjoe.services.user;

import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.hotjoe.jwt.JWTTokenUtil;
import com.hotjoe.services.user.model.CreateTokenRequest;
import com.hotjoe.services.user.model.CreateTokenResponse;
import com.hotjoe.services.user.model.ValidateTokenRequest;
import com.hotjoe.services.user.model.ValidateTokenResponse;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.parameters.RequestBody;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.jboss.logging.Logger;

import jakarta.annotation.PostConstruct;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;


/**
 * An example JAX-RS based service that allows you to generate and validate JWT tokens.  This example uses a
 * configurable but hardly production caliber username and password that is used to generate the token.  A real
 * environment would use some other way of to validate the credentials from a database to removing this entirely
 * and using a real auth system.  But as this is meant as an example we're doing it in an incredibly simple way.
 *
 */
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

    /**
     * Get a JWT via a GET and URL parameters.  The request URL simply contains the username and password.  I'd argue
     * that this is a less secure than the POST version as the URL is a bit easier to sniff.  But as this is all
     * example code it is useful to be able to see the request and response in a browser easily.
     **
     * @return a jakarta.ws.rs.core.Response that contains either an error message (non 200 response) or a
     *         CreateTokenResponse that contains the JWT.  @see com.hotjoe.model.CreateTokenResponse
     *
     */
    @Path("/getToken")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Generate a JWT based on the given credentials.")
    @APIResponse(content = @Content(schema = @Schema(implementation = CreateTokenResponse.class)),
            responseCode = "200",
            description = "The new JWT for use in future calls")
    @APIResponse(responseCode = "401", description = "If the passed credentials are incorrect")
    @APIResponse(responseCode = "400", description = "If the passed credentials are empty or missing")
    public Response getToken( @QueryParam("username") String requestedUsername,
                              @QueryParam("password") String requestedPassword) {
        CreateTokenRequest createTokenRequest = new CreateTokenRequest();

        createTokenRequest.setUserName(requestedUsername);
        createTokenRequest.setPassword(requestedPassword);

        return generateToken(createTokenRequest);
    }

    /**
     * Get a JWT via a POST and a request body.  The request body simply contains the username and password.
     *
     * @param createTokenRequest a CreateTokenRequest - @see com.hotjoe.model.CreateTokenRequest.
     *
     * @return a jakarta.ws.rs.core.Response that contains either an error message (non 200 response) or a
     *         CreateTokenResponse that contains the JWT.  @see com.hotjoe.model.CreateTokenResponse
     *
     */
    @Path("/getToken")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Generate a JWT based on the given credentials.")
    @APIResponse(content = @Content(schema = @Schema(implementation = CreateTokenResponse.class)),
            responseCode = "200",
            description = "The new JWT for use in future calls")
    @APIResponse(responseCode = "401", description = "If the passed credentials are incorrect")
    @APIResponse(responseCode = "400", description = "If the passed credentials are empty or missing")
    public Response getToken( @RequestBody( name="createTokenRequest",
            required = true,
            description = "The credentials used to validate and generate a token",
            content = @Content(schema = @Schema(implementation = CreateTokenRequest.class)) )
                                  CreateTokenRequest createTokenRequest) {
        return generateToken(createTokenRequest);
    }

    /**
     * Validate a JWT via a POST.  The request body simply contains the token.
     *
     * @param validateTokenRequest a CreateTokenRequest - @see com.hotjoe.model.ValidateTokenRequest.
     *
     * @return a jakarta.ws.rs.core.Response that contains either an error message (non 200 response) or a
     *         ValidateTokenResponse that contains the JWT.  @see com.hotjoe.model.ValidateTokenResponse
     *
     */
    @Path("/validateToken")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Validates a JWT based that was generated with this code.  This is not a general validator.")
    @APIResponse(content = @Content(schema = @Schema(implementation = ValidateTokenRequest.class)),
            responseCode = "200",
            description = "The JWT is valid")
    @APIResponse(responseCode = "400", description = "If the passed JWT is invalid")
    public Response validateToken(@RequestBody( name="createTokenRequest",
            required = true,
            description = "The validation result",
            content = @Content(schema = @Schema(implementation = ValidateTokenResponse.class)) )
                                      ValidateTokenRequest validateTokenRequest) {
        ValidateTokenResponse validateTokenResponse = new ValidateTokenResponse();

        try {
            jwtTokenUtil.validateToken(validateTokenRequest.getToken());
            validateTokenResponse.setResponse("token ok");

            return Response.status(Response.Status.OK)
                    .entity(validateTokenResponse).build();
        }
        catch(JWTCreationException | SignatureVerificationException jwtCreationException) {
            validateTokenResponse.setResponse(jwtCreationException.getMessage());

            //
            // does BAD_REQUEST make sense here?  auth0 doesn't split out *what* the error is, just that it
            // failed.  in a real system i'd want to know things like bad signature, expired, etc. that way
            // a more intelligible http response code could be sent
            //
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(validateTokenResponse).build();
        }
    }


    /**
     * Generates the token from the requested parameters.
     * @param createTokenRequest a CreateTokenRequest - @see com.hotjoe.model.CreateTokenRequest.
     *
     * @return a jakarta.ws.rs.core.Response that contains either an error message (non 200 response) or a
     *         CreateTokenResponse that contains the JWT.  @see com.hotjoe.model.CreateTokenResponse
     *
     */
    private Response generateToken(CreateTokenRequest createTokenRequest) {
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
