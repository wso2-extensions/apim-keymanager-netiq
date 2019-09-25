/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * you may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.nam.client;

/**
 * Constants for NetIQ key manager implementation.
 */
class NAMConstants {
    static final String UTF_8 = "UTF-8";
     static final String URL_RESOURCE_SEPERATOR = "/";
     static final String CONTENT_TYPE = "Content-Type";
     static final String APPLICATION_JSON = "application/json";
     static final String APPLICATIN_FORM_URL_ENCODED = "application/x-www-form-urlencoded";
     static final String AUTHORIZATION = "Authorization";
     static final String PASSWORD = "password";
     static final String USERNAME = "username";
     static final String BEARER = "Bearer ";
     static final String AUDIENCE = "audience";

     static final String CLIENT_ID = "client_id";
     static final String CLIENT_NAME = "client_name";
     static final String CLIENT_SECRET = "client_secret";
     static final String APPLICATION_TYPE = "application_type";
     static final String GRANT_TYPE = "grant_type";
     static final String GRANT_TYPES = "grant_types";
     static final String RESPONSE_TYPES = "response_types";
     static final String ALWAYS_ISSUE_NEW_REFRESH_TOKEN = "alwaysIssueNewRefreshToken";
     static final String AUTH_CODE_TTL =  "authzCodeTTL";
     static final String ACCESS_TOKEN_TTL = "accessTokenTTL";
     static final String REFRESH_TOKEN_TTL = "refreshTokenTTL";
     static final String CORS_DOMAINS = "corsdomains";
     static final String LOGO_URI = "logo_uri";
     static final String POLICY_URI = "policy_uri";
     static final String TOS_URI = "tos_uri";
     static final String CONTACTS = "contacts";
     static final String JWKS_URI = "jwks_uri";
     static final String ID_TOKEN_SIGNED_RESPONSE_ALG = "id_token_signed_response_alg";
     static final String ID_TOKEN_ENCRYPTED_RESPONSE_ALG = "id_token_encrypted_response_alg";
     static final String ID_TOKEN_ENCRYPTED_RESPONSE_ENC = "id_token_encrypted_response_enc";
     static final String REDIRECT_URIS = "redirect_uris";
     static final String ACCESS_TOKEN = "access_token";
     static final String SCOPE = "scope";
     static final String EXPIRES_IN = "expires_in";
     static final String  TOKEN_SCOPE = "tokenScope";
     static final String USER_ID = "user_id";
     static final String ISSUER = "issuer";
     static final String TOKEN_ID = "token_id";
     static final String KEY_TYPE = "key_type";

     static final String CONFIG_CLIENT_ID = "ClientId";
     static final String CONFIG_CLIENT_SECRET = "ClientSecret";
     static final String CONFIG_USERNAME = "Username";
     static final String CONFIG_PASSWORD = "Password";
     static final String CONFIG_NAM_INSTANCE_URL = "ServerURL";
     static final String CONFIG_NAM_CLIENT_ENDPOINT = "ClientEndpoint";
     static final String CONFIG_NAM_TOKEN_ENDPOINT = "TokenEndpoint";
     static final String CONFIG_NAM_TOKENINFO_ENDPOINT = "TokenInfoEndpoint";

     static final String INFO_TOKEN_INFO = "tokenInfo";
     static final String INFO_TOKEN_GRANT_TYPE = "tokenGrantType";

     static final String NAM_SCOPE_SEPARATOR = " ";
     static final String NAM_GRANT_TYPE_SEPARATOR = " ";
     static final String INFO_SCOPE_SEPARATOR = ",";
     static final String INFO_GRANT_TYPE_SEPARATOR = ",";
     static final String URI_SEPARATOR = ",";

     static final String ERROR_COULD_NOT_READ_HTTP_ENTITY = "Could not read http entity for response";
     static final String STRING_FORMAT = "%s %s";
     static final String ERROR_CLIENT_PROTOCOL =
            "HTTP error has occurred while sending request to OAuth Provider.";

     static final String DEFAULT_SCOPE = "urn:netiq.com:nam:scope:oauth:registration:full";
     static final String DEFAULT_REDIRECT_URI = "https://client.example.org/callback";
     static final String DEFAULT_RESPONSE_TYPE = "code";
     static final String TOKEN_SCOPE_SPLIT_REGEX = "\\s+";

     static final String MANDATORY_CONFIG_PROPERTY_MISSING = "Mandatory property %s is missing in the " +
            "configurations.";
}
