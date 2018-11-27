/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.AccessTokenInfo;
import org.wso2.carbon.apimgt.api.model.AccessTokenRequest;
import org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration;
import org.wso2.carbon.apimgt.api.model.OAuthAppRequest;
import org.wso2.carbon.apimgt.api.model.OAuthApplicationInfo;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.AbstractKeyManager;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class NamOauthClient extends AbstractKeyManager {
    private static final Log log = LogFactory.getLog(NamOauthClient.class);
    private KeyManagerConfiguration configuration;
    private String namInstanceURL;
    private String apiKey;

    @Override
    public void loadConfiguration(KeyManagerConfiguration keyManagerConfiguration) throws APIManagementException {
        this.configuration = keyManagerConfiguration;
        namInstanceURL = configuration.getParameter(NAMConstants.NAM_INSTANCE_URL);
        apiKey = configuration.getParameter(NAMConstants.REGISTRAION_API_KEY);
    }

    @Override
    public OAuthApplicationInfo createApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
        OAuthApplicationInfo oAuthApplicationInfo = oAuthAppRequest.getOAuthApplicationInfo();
        String clientName = oAuthApplicationInfo.getClientName();

        if (log.isDebugEnabled()) {
            log.debug(String.format("Creating an OAuth client in NetIQ authorization server with application name %s",
                    clientName));
        }

        String scope = (String) oAuthApplicationInfo.getParameter(NAMConstants.TOKEN_SCOPE);
        Object tokenGrantType = oAuthApplicationInfo.getParameter(NAMConstants.TOKEN_GRANT_TYPE);

        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        String registrationEndpoint = namInstanceURL + NAMConstants.CLIENT_ENDPOINT;
        List<NameValuePair> params = new ArrayList<NameValuePair>();
        UrlEncodedFormEntity urlEncodedFormEntity = createPayloadFromOAuthAppInfo(oAuthApplicationInfo, params);

        HttpPost httpPost = new HttpPost(registrationEndpoint);
        try {
            httpPost.setHeader(NAMConstants.CONTENT_TYPE, NAMConstants.APPLICATIN_FORM_URL_ENCODED);
            httpPost.setHeader(NAMConstants.AUTHORIZATION, NAMConstants.BEARER  + apiKey);
            httpPost.setEntity(urlEncodedFormEntity);

            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                handleException(String.format(NAMConstants.STRING_FORMAT,
                        NAMConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY, response));
            }

            BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), NAMConstants.UTF_8));
            JSONObject responseObject = getParsedObjectByReader(reader);

            //TODO : Handle response and generate oAuthApplicationInfo
            // If successful a 201 will be returned.
            if (HttpStatus.SC_CREATED == statusCode) {
                if (responseObject != null) {
                    oAuthApplicationInfo = createOAuthAppInfoFromResponse(responseObject);
                    if (!StringUtils.isEmpty(scope)) {
                        oAuthApplicationInfo.addParameter(NAMConstants.TOKEN_SCOPE, scope);
                    }
                    if (tokenGrantType != null) {
                        oAuthApplicationInfo.addParameter(NAMConstants.TOKEN_GRANT_TYPE, tokenGrantType);
                    }
                    return oAuthApplicationInfo;
                }
            } else {
                handleException(String.format("Error occured while registering the new client in NetIQ Access Manager" +
                        ".Response : %s", responseObject.toJSONString()));
            }

        } catch (UnsupportedEncodingException e) {
            handleException(String.format("Unsupported encoding method has been used when creating a client " +
                    "application for %s.", oAuthApplicationInfo.getClientId()), e);
        } catch (ClientProtocolException e) {
            throw new APIManagementException(NAMConstants.ERROR_CLIENT_PROTOCOL, e);
        } catch (IOException e) {
            handleException(String.format("Error occurred while reading response body when creating a client " +
                    "application for %s.", oAuthApplicationInfo.getClientId()), e);
        } catch (ParseException e) {
            handleException(String.format("Error occurred while parsing response when creating a client application " +
                    "for %s.", oAuthApplicationInfo.getClientId()), e);
        }
        return null;
    }

    @Override
    public OAuthApplicationInfo updateApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
        OAuthApplicationInfo oAuthApplicationInfo = oAuthAppRequest.getOAuthApplicationInfo();
        // We have to send the client id with the update request.
        String clientId = oAuthApplicationInfo.getClientId();
        if (log.isDebugEnabled()) {
            log.debug(String.format("Updating an OAuth client in NetIQ authorization server for the consumer Key %s",
                    clientId));
        }
        // Getting Client Instance Url and API Key from Config.
        String updateEndpoint = namInstanceURL + NAMConstants.CLIENT_ENDPOINT + "/" + clientId;

        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        BufferedReader reader = null;
        List<NameValuePair> params = new ArrayList<NameValuePair>();
        if (StringUtils.isNotEmpty(clientId)) {
            params.add(new BasicNameValuePair(NAMConstants.CLIENT_ID, clientId));
        }
        try {
            // Create the JSON Payload that should be sent to OAuth Server.
            UrlEncodedFormEntity urlEncodedFormEntity = createPayloadFromOAuthAppInfo(oAuthApplicationInfo, params);
            HttpPut httpPut = new HttpPut(updateEndpoint);
            httpPut.setEntity(urlEncodedFormEntity);
            httpPut.setHeader(NAMConstants.CONTENT_TYPE, NAMConstants.APPLICATION_JSON);
            // Setting Authorization Header, with API Key.
            httpPut.setHeader(NAMConstants.AUTHORIZATION, NAMConstants.BEARER + apiKey);
            if (log.isDebugEnabled()) {
                log.debug(String.format("Invoking HTTP request to update client in NetIQ Access Manager for " +
                                "consumer key %s", clientId));
            }
            HttpResponse response = httpClient.execute(httpPut);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                handleException(String.format(NAMConstants.STRING_FORMAT, NAMConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY,
                        response));
            }
            reader = new BufferedReader(new InputStreamReader(entity.getContent(), NAMConstants.UTF_8));
            JSONObject responseObject = getParsedObjectByReader(reader);
            if (statusCode == HttpStatus.SC_OK) {
                if (responseObject != null) {
                    return createOAuthAppInfoFromResponse(responseObject);
                } else {
                    handleException("ResponseObject is empty. Can not return oAuthApplicationInfo.");
                }
            } else {
                handleException(String.format("Error occurred when updating the client with consumer key %s" +
                        " : Response: %s", clientId, responseObject.toJSONString()));
            }
        } catch (UnsupportedEncodingException e) {
            handleException(String.format("Unsupported encoding method has been used while updating client " +
                    "application for %s.", clientId), e);
        } catch (IOException e) {
            handleException(String.format("Error occurred when reading response body while updating client " +
                            "application for %s.", clientId), e);
        } catch (ParseException e) {
            handleException(String.format("Error occurred when parsing response while updating client application " +
                            "for %s.", clientId), e);
        } finally {
            closeResources(reader, httpClient);
        }
        return null;
    }

    @Override
    public void deleteApplication(String clientId) throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Deleting an OAuth client in NetIQ authorization server for the Consumer Key: %s",
                    clientId));
        }
        // Getting Client Instance Url and API Key from Config.
        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        String deleteEndpoint = namInstanceURL + NAMConstants.CLIENT_ENDPOINT + "/"
                + clientId;

        HttpDelete httpDelete = new HttpDelete(deleteEndpoint);
        // TODO : how should these requests be authenticated
        httpDelete.setHeader(NAMConstants.AUTHORIZATION, NAMConstants.BEARER + apiKey);
        BufferedReader reader = null;
        try {
            HttpResponse response = httpClient.execute(httpDelete);
            int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode == HttpStatus.SC_NO_CONTENT) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("OAuth Client for the Consumer Key %s has been successfully deleted",
                            clientId));
                }
            } else {
                HttpEntity entity = response.getEntity();
                if (entity == null) {
                    handleException(String.format("Could not read http entity for response %s while deleting " +
                            "client : %s ", response, clientId));
                }
                reader = new BufferedReader(new InputStreamReader(entity.getContent(),
                        NAMConstants.UTF_8));
                JSONObject responseObject = getParsedObjectByReader(reader);
                handleException(String.format("Problem occurred while deleting client for the Consumer Key %s." +
                        " Response : %s", clientId, responseObject.toJSONString()));
            }

        } catch (IOException e) {
            handleException(String.format("Error occurred when reading response body while deleting client %s.",
                    clientId), e);
        } catch (ParseException e) {
            handleException(String.format("Error occurred when parsing response while deleting client %s.",
                    clientId), e);
        } finally {
            closeResources(reader, httpClient);
        }
    }

    @Override
    public OAuthApplicationInfo retrieveApplication(String clientId) throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Retrieving an OAuth client from NetIQ authorization server for the consumer key" +
                    " %s", clientId));
        }

        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        String registrationEndpoint = namInstanceURL + NAMConstants.CLIENT_ENDPOINT;

        BufferedReader reader = null;
        try {
            HttpGet request = new HttpGet(registrationEndpoint);
            // Set authorization header, with API key.
            request.addHeader(NAMConstants.AUTHORIZATION, NAMConstants.BEARER + apiKey);
            if (log.isDebugEnabled()) {
                log.debug(String.format("Invoking HTTP request to get the client details for the consumer key %s",
                        clientId));
            }
            HttpResponse response = httpClient.execute(request);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                handleException(String.format(NAMConstants.STRING_FORMAT,
                        NAMConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY, response));
            }
            reader = new BufferedReader(new InputStreamReader(entity.getContent(), NAMConstants.UTF_8));
            Object responseJSON;

            if (statusCode == HttpStatus.SC_OK) {
                JSONParser parser = new JSONParser();
                responseJSON = parser.parse(reader);
                return createOAuthAppInfoFromResponse((JSONObject) responseJSON);
            } else {
                handleException(String.format("Error occurred while retrieving client application for consumer " +
                                "key %s.", clientId));
            }
        } catch (ParseException e) {
            handleException(String.format("Error occurred while parsing response when retrieving client application " +
                            "for %s.", clientId), e);
        } catch (IOException e) {
            handleException(String.format("Error while reading response body when retrieving client application of %s.",
                    clientId), e);
        } finally {
            closeResources(reader, httpClient);
        }
        return null;
    }


    @Override
    public AccessTokenInfo getNewApplicationAccessToken(AccessTokenRequest accessTokenRequest)
            throws APIManagementException {
        AccessTokenInfo tokenInfo = new AccessTokenInfo();
        String refreshToken = accessTokenRequest.getRefreshToken();
        String grantType = accessTokenRequest.getGrantType();
        String clientId = accessTokenRequest.getClientId();
        String clientSecret = accessTokenRequest.getClientSecret();

        if (log.isDebugEnabled()) {
            log.debug(String.format("Get new client access token from authorization server for the consumer key %s",
                    clientId));
        }

        revokeAccessToken(clientId, clientSecret, refreshToken);
        List<NameValuePair> parameters = new ArrayList<NameValuePair>();
        if (grantType == null) {
            grantType = NAMConstants.CLIENT_CREDENTIALS;
        }
        parameters.add(new BasicNameValuePair(NAMConstants.GRANT_TYPE, grantType));

        String scopeString = convertToString(accessTokenRequest.getScope());
        if (StringUtils.isEmpty(scopeString)) {
            parameters.add(new BasicNameValuePair(NAMConstants.SCOPE, scopeString));
        }

        JSONObject responseJSON = getAccessToken(clientId, clientSecret, parameters);
        if (responseJSON != null) {
            updateTokenInfo(tokenInfo, responseJSON);
            if (log.isDebugEnabled()) {
                log.debug(String.format("OAuth token has been successfully validated for the consumer key %s.",
                        clientId));
            }
            return tokenInfo;
        } else {
            tokenInfo.setTokenValid(false);
            tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_INVALID_CREDENTIALS);
            if (log.isDebugEnabled()) {
                log.debug(String.format("OAuth token validation failed for the consumer key %s.", clientId));
            }
        }
        return tokenInfo;
    }

    @Override
    public AccessTokenInfo getTokenMetaData(String accessToken) throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Getting access token metadata from authorization server. Access token %s",
                    accessToken));
        }
        String tokenInfoEndpoint = namInstanceURL + NAMConstants.TOKEN_INFO_ENDPOINT;
        AccessTokenInfo tokenInfo = new AccessTokenInfo();
        CloseableHttpClient httpClient = HttpClientBuilder.create().build();

        HttpGet httpGet = new HttpGet(tokenInfoEndpoint);
        httpGet.setHeader(NAMConstants.AUTHORIZATION, NAMConstants.BEARER + accessToken);
        BufferedReader reader;
        JSONObject jsonResponse;
        try {
            HttpResponse response = httpClient.execute(httpGet);
            int statusCode = response.getStatusLine().getStatusCode();

            if (HttpStatus.SC_OK == statusCode) {
                HttpEntity entity = response.getEntity();
                if (entity == null) {
                    handleException(String.format("Failed to read http entity from response %s " +
                            "while getting token meta data.", response));
                }

                reader = new BufferedReader(new InputStreamReader(entity.getContent(), NAMConstants.UTF_8));
                jsonResponse = getParsedObjectByReader(reader);

                if (jsonResponse == null) {
                    log.error(String.format("Invalid token %s", accessToken));
                    tokenInfo.setTokenValid(false);
                    tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_INVALID_CREDENTIALS);
                    return tokenInfo;
                }
                // handle responses
            }
        } catch (IOException e) {
            handleException("Error occurred when reading the response while getting token meta data.", e);
        } catch (ParseException e) {
            handleException("Error occurred when parsing response while getting token meta data.", e);
        }
        return null;
    }

    @Override
    public KeyManagerConfiguration getKeyManagerConfiguration() throws APIManagementException {
        return configuration;
    }

    @Override
    public OAuthApplicationInfo buildFromJSON(String s) throws APIManagementException {
        return null;
    }

    @Override
    public OAuthApplicationInfo mapOAuthApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
        return oAuthAppRequest.getOAuthApplicationInfo();
    }

    @Override
    public boolean registerNewResource(API api, Map map) throws APIManagementException {
        return true;
    }

    @Override
    public Map getResourceByApiId(String s) throws APIManagementException {
        return null;
    }

    @Override
    public boolean updateRegisteredResource(API api, Map map) throws APIManagementException {
        return true;
    }

    @Override
    public void deleteRegisteredResourceByAPIId(String s) throws APIManagementException {
        // not applicable
    }

    @Override
    public void deleteMappedApplication(String s) throws APIManagementException {
        // not applicable
    }

    @Override
    public Set<String> getActiveTokensByConsumerKey(String s) throws APIManagementException {
        return Collections.emptySet();
    }

    @Override
    public AccessTokenInfo getAccessTokenByConsumerKey(String s) throws APIManagementException {
        return null;
    }

    private OAuthApplicationInfo createOAuthAppInfoFromResponse(JSONObject response) throws APIManagementException {
        OAuthApplicationInfo appInfo = new OAuthApplicationInfo();

        String clientId = (String) response.get(NAMConstants.CLIENT_ID);
        String clientName = (String) response.get(NAMConstants.CLIENT_NAME);
        String clientSecret = (String) response.get(NAMConstants.CLIENT_SECRET);

        if (StringUtils.isEmpty(clientId)) {
            handleException(String.format("Mandatory parameter %s is empty in the response %s.",
                    NAMConstants.CLIENT_ID, response.toJSONString()));
        }
        appInfo.setClientId((String) response.get(NAMConstants.CLIENT_ID));

        if (!StringUtils.isEmpty(clientName)) {
            appInfo.setClientName(clientName);
            appInfo.addParameter(NAMConstants.CLIENT_NAME, clientName);
        }

        if (!StringUtils.isEmpty(clientSecret)) {
            appInfo.setClientSecret(clientSecret);
        }

        JSONArray redirectUris = (JSONArray) response.get(NAMConstants.REDIRECT_URIS);
        if (redirectUris != null) {
            appInfo.setCallBackURL((String) redirectUris.toArray()[0]);
            appInfo.addParameter(NAMConstants.REDIRECT_URIS, redirectUris);
        }

        if (response.get(NAMConstants.GRANT_TYPES) != null) {
            appInfo.addParameter(NAMConstants.GRANT_TYPES, response.get(NAMConstants.GRANT_TYPES));
        }

        return appInfo;
    }

    private static void handleException(String msg, Exception e) throws APIManagementException {
        log.error(msg, e);
        throw new APIManagementException(msg, e);
    }

    private static void handleException(String msg) throws APIManagementException {
        log.error(msg);
        throw new APIManagementException(msg);
    }

    private static UrlEncodedFormEntity createPayloadFromOAuthAppInfo(OAuthApplicationInfo appInfo,
                                       List<NameValuePair> params) throws APIManagementException {

        String clientId = appInfo.getClientId();
        if (StringUtils.isEmpty(clientId)) {
            handleException("Mandatory parameter " + NAMConstants.CLIENT_ID + " is missing.");
        }
        params.add(new BasicNameValuePair(NAMConstants.CLIENT_ID, clientId));

        String redirectionUri = appInfo.getCallBackURL();
        if (StringUtils.isEmpty(redirectionUri)) {
            handleException("Mandatory parameter redirection uris is missing.");
        }
        params.add(new BasicNameValuePair(NAMConstants.REDIRECTION_URI, redirectionUri));

        String grantTypes = (String) appInfo.getParameter(NAMConstants.GRANT_TYPES);
        if (grantTypes != null) {
            JSONArray jsonArray = new JSONArray();
            Collections.addAll(jsonArray, grantTypes.split(","));
            params.add(new BasicNameValuePair(NAMConstants.GRANT_TYPES, jsonArray.toJSONString()));
        }

        String clientName = appInfo.getClientName();
        if (!StringUtils.isEmpty(clientName)) {
            params.add(new BasicNameValuePair(NAMConstants.CLIENT_NAME, clientName));
        }

        JSONObject jsonObject;
        String jsonString = appInfo.getJsonString();
        try {
             jsonObject = (JSONObject) new JSONParser().parse(jsonString);
        } catch (ParseException e) {
            throw new APIManagementException("Error while parsing json string of oAuthApplicationInfo " +
                    jsonString);
        }

        if (jsonObject != null) {
            String applicationType = (String) jsonObject.get(NAMConstants.APPLICATION_TYPE);
            if (!StringUtils.isEmpty(applicationType)) {
                params.add(new BasicNameValuePair(NAMConstants.APPLICATION_TYPE, applicationType));
            }

            String responseTypes = (String) jsonObject.get(NAMConstants.RESPONSE_TYPES);
            if (!StringUtils.isEmpty(responseTypes)) {
                params.add(new BasicNameValuePair(NAMConstants.RESPONSE_TYPES, responseTypes));
            }

            String alwaysIssueNewRefreshToken = (String) jsonObject.get(NAMConstants.ALWAYS_ISSUE_NEW_REFRESH_TOKEN);
            if (!StringUtils.isEmpty(alwaysIssueNewRefreshToken)) {
                params.add(new BasicNameValuePair(NAMConstants.ALWAYS_ISSUE_NEW_REFRESH_TOKEN, alwaysIssueNewRefreshToken));
            }

            String authzCodeTTL = (String) jsonObject.get(NAMConstants.AUTH_CODE_TTL);
            if (!StringUtils.isEmpty(authzCodeTTL)) {
                params.add(new BasicNameValuePair(NAMConstants.AUTH_CODE_TTL, authzCodeTTL));
            }

            String accessTokenTTL = (String) jsonObject.get(NAMConstants.ACCESS_TOKEN_TTL);
            if (!StringUtils.isEmpty(accessTokenTTL)) {
                params.add(new BasicNameValuePair(NAMConstants.ACCESS_TOKEN_TTL, accessTokenTTL));
            }

            String refreshTokenTTL = (String) jsonObject.get(NAMConstants.REFRESH_TOKEN_TTL);
            if (!StringUtils.isEmpty(refreshTokenTTL)) {
                params.add(new BasicNameValuePair(NAMConstants.REFRESH_TOKEN_TTL, refreshTokenTTL));
            }

            String corsdomains = (String) jsonObject.get(NAMConstants.CORS_DOMAINS);
            if (!StringUtils.isEmpty(corsdomains)) {
                params.add(new BasicNameValuePair(NAMConstants.CORS_DOMAINS, corsdomains));
            }

            String logoUri = (String) jsonObject.get(NAMConstants.LOGO_URI);
            if (!StringUtils.isEmpty(logoUri)) {
                params.add(new BasicNameValuePair(NAMConstants.LOGO_URI, logoUri));
            }

            String policyUri = (String) jsonObject.get(NAMConstants.POLICY_URI);
            if (!StringUtils.isEmpty(policyUri)) {
                params.add(new BasicNameValuePair(NAMConstants.POLICY_URI, policyUri));
            }

            String tosUri = (String) jsonObject.get(NAMConstants.TOS_URI);
            if (!StringUtils.isEmpty(tosUri)) {
                params.add(new BasicNameValuePair(NAMConstants.TOS_URI, tosUri));
            }

            String contacts = (String) jsonObject.get(NAMConstants.CONTACTS);
            if (!StringUtils.isEmpty(contacts)) {
                params.add(new BasicNameValuePair(NAMConstants.CONTACTS, contacts));
            }

            String jwksUri = (String) jsonObject.get(NAMConstants.JWKS_URI);
            if (!StringUtils.isEmpty(jwksUri)) {
                params.add(new BasicNameValuePair(NAMConstants.JWKS_URI, jwksUri));
            }

            String idTokenSignedResponseAlg = (String) jsonObject.get(NAMConstants.ID_TOKEN_SIGNED_RESPONSE_ALG);
            if (!StringUtils.isEmpty(idTokenSignedResponseAlg)) {
                params.add(new BasicNameValuePair(NAMConstants.ID_TOKEN_SIGNED_RESPONSE_ALG, idTokenSignedResponseAlg));
            }

            String idTokenEncryptedResponseAlg =
                    (String) jsonObject.get(NAMConstants.ID_TOKEN_ENCRYPTED_RESPONSE_ALG);
            if (!StringUtils.isEmpty(idTokenEncryptedResponseAlg)) {
                params.add(new BasicNameValuePair(NAMConstants.ID_TOKEN_ENCRYPTED_RESPONSE_ALG,
                        idTokenEncryptedResponseAlg));
            }

            String idTokenEnctryptedResponseEnc =
                    (String) jsonObject.get(NAMConstants.ID_TOKEN_ENCRYPTED_RESPONSE_ENC);
            if (!StringUtils.isEmpty(idTokenEnctryptedResponseEnc)) {
                params.add(new BasicNameValuePair(NAMConstants.ID_TOKEN_ENCRYPTED_RESPONSE_ENC,
                        idTokenEnctryptedResponseEnc));
            }
        }

        try {
            return new UrlEncodedFormEntity(params);
        } catch (UnsupportedEncodingException e) {
            throw new APIManagementException(NAMConstants.ERROR_ENCODING_METHOD_NOT_SUPPORTED, e);
        }
    }

    private void revokeAccessToken(String clientId, String clientSecret, String refreshToken)
            throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Revoke access token from authorization Server."));
        }

        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        if (StringUtils.isEmpty(clientId)) {
            handleException("Client id cannot be empty for a revoke token request");
        }
        if (StringUtils.isEmpty(refreshToken)) {
            handleException("Refresh token cannot be empty for a revoke token request.");
        }

        try {
            List<NameValuePair> params = new ArrayList<NameValuePair>();
            params.add(new BasicNameValuePair(NAMConstants.TOKEN, refreshToken)); //todo: verify the key token or
            // refresh_token
            HttpPost httpPost = new HttpPost(namInstanceURL + NAMConstants.REVOKE_ENDPOINT);
            httpPost.setEntity(new UrlEncodedFormEntity(params));
            String encodedCredentials = getEncodedCredentials(clientId, clientSecret);
            httpPost.setHeader(NAMConstants.AUTHORIZATION, NAMConstants.AUTHENTICATION_BASIC + encodedCredentials);

            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to revoke access token.");
            }
            HttpResponse response = httpClient.execute(httpPost);
            // TODO: 16/11/18 Handle response (error code)
            int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode == HttpStatus.SC_OK) {
                if (log.isDebugEnabled()) {
                    log.debug("OAuth accessToken has been successfully revoked.");
                }
            } else {
                handleException(String.format("Problem occurred while revoking the access token for consumer key %s.",
                        clientId));
            }
        } catch (UnsupportedEncodingException e) {
            handleException(String.format("Unsupported encoding has been used while revoking token for %s.",
                    clientId), e);
        } catch (ClientProtocolException e) {
            handleException(String.format("HTTP error has occurred when sending request to OAuth Provider while " +
                    "revoking token for %s.", clientId), e);
        } catch (IOException e) {
            handleException(String.format("Error when reading response body while revoking token for %s.",
                    clientId), e);
        } finally {
            try {
                if (httpClient != null) {
                    httpClient.close();
                }
            } catch (IOException e) {
                log.error(e);
            }
        }
    }

    private JSONObject getParsedObjectByReader(BufferedReader reader) throws ParseException, IOException {
        JSONObject parsedObject = null;
        JSONParser parser = new JSONParser();
        if (reader != null) {
            parsedObject = (JSONObject) parser.parse(reader);
        }
        return parsedObject;
    }

    private void closeResources(BufferedReader reader, CloseableHttpClient httpClient) {
        if (reader != null) {
            IOUtils.closeQuietly(reader);
        }
        try {
            if (httpClient != null) {
                httpClient.close();
            }
        } catch (IOException e) {
            log.error(e);
        }
    }

    private JSONObject getAccessToken(String clientId, String clientSecret, List<NameValuePair> parameters) throws
            APIManagementException {
        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        BufferedReader reader = null;

        try {
            HttpPost httpPost = new HttpPost(namInstanceURL + NAMConstants.TOKEN_ENDPOINT);
            httpPost.setEntity(new UrlEncodedFormEntity(parameters));
            String encodedCredentials = getEncodedCredentials(clientId, clientSecret);

            httpPost.setHeader(NAMConstants.AUTHORIZATION, NAMConstants.AUTHENTICATION_BASIC + encodedCredentials);
            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to get the access token for client " + clientId);
            }
            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                handleException(String.format(NAMConstants.STRING_FORMAT,
                        NAMConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY, response));
            }
            reader = new BufferedReader(new InputStreamReader(entity.getContent(), NAMConstants.UTF_8));
            JSONObject responseJSON = getParsedObjectByReader(reader);

            if (HttpStatus.SC_OK == statusCode) {
                if (responseJSON != null) {
                    if (log.isDebugEnabled()) {
                        log.debug(String.format("JSON response after getting new access token: %s",
                                responseJSON.toJSONString()));
                    }
                    return responseJSON;
                }
            } else {
                log.error(String.format("Failed to get accessToken for Consumer Key %s. Response: %s", clientId,
                        responseJSON.toJSONString()));
            }
        } catch (UnsupportedEncodingException e) {
            handleException(String.format("Error occurred when encoding while getting a new access token for %s.",
                    clientId), e );
        } catch (ParseException e) {
            handleException(String.format("Error occurred when parsing the response while getting a new access token " +
                    "for %s.", clientId), e);
        } catch (IOException e) {
            handleException(String.format("Error occurred when reading response body while getting a new access token" +
                    " client %s.", clientId), e);
        } finally {
            closeResources(reader, httpClient);
        }
        return null;
    }

    private AccessTokenInfo updateTokenInfo(AccessTokenInfo tokenInfo, JSONObject responseJSON) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Update the access token info with JSON response: %s, after getting " +
                    "new access token.", responseJSON));
        }
        Long expireTime = (Long) responseJSON.get(NAMConstants.EXPIRES_IN);
        if (expireTime == null) {
            tokenInfo.setTokenValid(false);
            tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_INVALID_CREDENTIALS);
            return tokenInfo;
        }

        tokenInfo.setAccessToken((String) responseJSON.get(NAMConstants.ACCESS_TOKEN));
        tokenInfo.setValidityPeriod(expireTime * 1000);

        String tokenScopes = (String) responseJSON.get(NAMConstants.SCOPE);
        if (StringUtils.isNotEmpty(tokenScopes)) {
            tokenInfo.setScope(tokenScopes.split("\\s+"));
        }
        return tokenInfo;
    }

    private static String convertToString(String[] stringArray) {
        if (stringArray != null) {
            StringBuilder sb = new StringBuilder();
            List<String> strList = Arrays.asList(stringArray);
            for (String s : strList) {
                sb.append(s);
                sb.append(" ");
            }
            return sb.toString().trim();
        }

        return null;
    }

    private static String getEncodedCredentials(String clientId, String clientSecret) throws APIManagementException {
        try {
            return Base64.getEncoder().encodeToString((clientId + ":" + clientSecret)
                    .getBytes(NAMConstants.UTF_8));
        } catch (UnsupportedEncodingException e) {
            throw new APIManagementException(NAMConstants.ERROR_ENCODING_METHOD_NOT_SUPPORTED, e);
        }
    }
}
