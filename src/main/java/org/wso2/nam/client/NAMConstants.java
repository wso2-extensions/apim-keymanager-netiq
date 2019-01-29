package org.wso2.nam.client;

/**
 * Constants for NetIQ key manager implementation.
 */
public class NAMConstants {
    public static final String UTF_8 = "UTF-8";
    public static final String CLIENT_ENDPOINT = "/nidp/oauth/nam/clients";
    public static final String TOKEN_ENDPOINT = "/nidp/oauth/nam/token";
    public static final String TOKEN_INFO_ENDPOINT = "/nidp/oauth/nam/tokeninfo";
    public static final String REVOKE_ENDPOINT = "/nidp/oauth/nam/revoke";
    public static final String URL_RESOURCE_SEPERATOR = "/";
    public static final String CONTENT_TYPE = "Content-Type";
    public static final String APPLICATION_JSON = "application/json";
    public static final String APPLICATIN_FORM_URL_ENCODED = "application/x-www-form-urlencoded";
    public static final String AUTHORIZATION = "Authorization";
    public static final String AUTHENTICATION_BASIC = "Basic ";
    public static final String PASSWORD = "password";
    public static final String USERNAME = "username";
    public static final String BEARER = "Bearer ";
    public static final String AUDIENCE = "audience";

    public static final String CLIENT_ID = "client_id";
    public static final String CLIENT_NAME = "client_name";
    public static final String CLIENT_SECRET = "client_secret";
    public static final String APPLICATION_TYPE = "application_type";
    public static final String GRANT_TYPE = "grant_type";
    public static final String GRANT_TYPES = "grant_types";
    public static final String RESPONSE_TYPES = "response_types";
    public static final String REDIRECTION_URI = "redirection_uri";
    public static final String ALWAYS_ISSUE_NEW_REFRESH_TOKEN = "alwaysIssueNewRefreshToken";
    public static final String AUTH_CODE_TTL =  "authzCodeTTL";
    public static final String ACCESS_TOKEN_TTL = "accessTokenTTL";
    public static final String REFRESH_TOKEN_TTL = "refreshTokenTTL";
    public static final String CORS_DOMAINS = "corsdomains";
    public static final String LOGO_URI = "logo_uri";
    public static final String POLICY_URI = "policy_uri";
    public static final String TOS_URI = "tos_uri";
    public static final String CONTACTS = "contacts";
    public static final String JWKS_URI = "jwks_uri";
    public static final String ID_TOKEN_SIGNED_RESPONSE_ALG = "id_token_signed_response_alg";
    public static final String ID_TOKEN_ENCRYPTED_RESPONSE_ALG = "id_token_encrypted_response_alg";
    public static final String ID_TOKEN_ENCRYPTED_RESPONSE_ENC = "id_token_encrypted_response_enc";
    public static final String REDIRECT_URIS = "redirect_uris";
    public static final String TOKEN = "token";
    public static final String ACCESS_TOKEN = "access_token";
    public static final String SCOPE = "scope";
    public static final String EXPIRES_IN = "expires_in";
    public static final String REFRESH_TOKEN = "refresh_token";
    public static final String CLIENT_CREDENTIALS = "client_credentials";
    public static final String  TOKEN_SCOPE = "tokenScope";
    public static final String USER_ID = "user_id";
    public static final String ISSUER = "issuer";
    public static final String TOKEN_ID = "token_id";
    public static final String KEY_TYPE = "key_type";
    public static final String SANDBOX = "SANDBOX";
    public static final String PRODUCTION = "PRODUCTION";
    public static final String SUFFIX_SANDBOX = "_sandbox";
    public static final String SUFFIX_PRODUCTION = "_production";

    public static final String CONFIG_CLIENT_ID = "ClientId";
    public static final String CONFIG_CLIENT_SECRET = "ClientSecret";
    public static final String CONFIG_USERNAME = "Username";
    public static final String CONFIG_PASSWORD = "Password";
    public static final String CONFIG_NAM_INSTANCE_URL = "ServerURL";

    public static final String INFO_TOKEN_INFO = "tokenInfo";
    public static final String INFO_TOKEN_GRANT_TYPE = "tokenGrantType";

    public static final String NAM_SCOPE_SEPERATOR = " ";
    public static final String NAM_GRANT_TYPE_SEPERATOR = " ";
    public static final String INFO_SCOPE_SEPERATOR = ",";
    public static final String INFO_GRANT_TYPE_SEPERATOR = ",";
    public static final String URI_SEPERATOR = ",";


    public static final String ERROR_ENCODING_METHOD_NOT_SUPPORTED = "Encoding method is not supported";
    public static final String ERROR_COULD_NOT_READ_HTTP_ENTITY = "Could not read http entity for response";
    public static final String STRING_FORMAT = "%s %s";
    public static final String ERROR_CLIENT_PROTOCOL =
            "HTTP error has occurred while sending request to OAuth Provider.";

    public static final String DEFAULT_SCOPE = "urn:netiq.com:nam:scope:oauth:registration:full";
    public static final String DEFAULT_REDIRECT_URI = "https://client.example.org/callback";
    public static final String DEFAULT_RESPONSE_TYPE = "code";
    public static final String DEFAULT_RESPONSE_TYPE_SEPERATOR = ",";

}