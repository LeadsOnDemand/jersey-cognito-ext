package com.anigenero.jersey.security.cognito.util;

public final class JWKUtil {

    public static String getIssuer(final String userPoolId) {
        return "https://cognito-idp.us-east-1.amazonaws.com/" + userPoolId;
    }

    public static String getJWKUrl(final String awsRegion, final String userPoolId) {
        return "https://cognito-idp." + awsRegion + ".amazonaws.com/" + userPoolId + "/.well-known/jwks.json";
    }

}
