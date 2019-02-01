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
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
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
import org.wso2.carbon.apimgt.api.model.Scope;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.AbstractKeyManager;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * This class contains the key manager implementation for WSO2 APIM considering Net IQ as the access manager.
 */
public class NamOauthClient extends AbstractKeyManager {
    private static final Log log = LogFactory.getLog(NamOauthClient.class);
    private KeyManagerConfiguration configuration;
    private String accessToken;
    private long accessTokenIssuedTime;
    private long validityPeriod;
    private String username;
    private String password;
    private String namAppClientId;
    private String namAppClientSecret;
    private String tokenEndpoint;
    private String tokenInfoEndpoint;
    private String clientEndpoint;

    @Override
    public void loadConfiguration(KeyManagerConfiguration keyManagerConfiguration) throws APIManagementException {
        configuration = keyManagerConfiguration;
        username = configuration.getParameter(NAMConstants.CONFIG_USERNAME);
        password = configuration.getParameter(NAMConstants.CONFIG_PASSWORD);
        namAppClientId = configuration.getParameter(NAMConstants.CONFIG_CLIENT_ID);
        namAppClientSecret = configuration.getParameter(NAMConstants.CONFIG_CLIENT_SECRET);
        tokenEndpoint = configuration.getParameter(NAMConstants.CONFIG_NAM_TOKEN_ENDPOINT);
        tokenInfoEndpoint = configuration.getParameter(NAMConstants.CONFIG_NAM_TOKENINFO_ENDPOINT);
        clientEndpoint = configuration.getParameter(NAMConstants.CONFIG_NAM_CLIENT_ENDPOINT);

        if (StringUtils.isEmpty(username)) {
            handleException(String.format(NAMConstants.MANDATORY_CONFIG_PROPERTY_MISSING, username));
        }

        if (StringUtils.isEmpty(password)) {
            handleException(String.format(NAMConstants.MANDATORY_CONFIG_PROPERTY_MISSING, password));
        }

        if (StringUtils.isEmpty(namAppClientId)) {
            handleException(String.format(NAMConstants.MANDATORY_CONFIG_PROPERTY_MISSING, namAppClientId));
        }

        if (StringUtils.isEmpty(namAppClientSecret)) {
            handleException(String.format(NAMConstants.MANDATORY_CONFIG_PROPERTY_MISSING, namAppClientSecret));
        }

        if (StringUtils.isEmpty(tokenEndpoint)) {
            handleException(String.format(NAMConstants.MANDATORY_CONFIG_PROPERTY_MISSING, tokenEndpoint));
        }

        if (StringUtils.isEmpty(tokenInfoEndpoint)) {
            handleException(String.format(NAMConstants.MANDATORY_CONFIG_PROPERTY_MISSING, tokenInfoEndpoint));
        }

        if (StringUtils.isEmpty(clientEndpoint)) {
            handleException(String.format(NAMConstants.MANDATORY_CONFIG_PROPERTY_MISSING, clientEndpoint));
        }
    }

    @Override
    public OAuthApplicationInfo createApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
        OAuthApplicationInfo oAuthApplicationInfo = oAuthAppRequest.getOAuthApplicationInfo();
        String clientName = oAuthApplicationInfo.getClientName();
        if (log.isDebugEnabled()) {
            log.debug(String.format("Creating an OAuth client in NetIQ authorization server with application name %s",
                    clientName));
        }

        updateNamAccessToken(oAuthApplicationInfo);
        OAuthApplicationInfo info = createApplication(oAuthApplicationInfo);
        return info;
    }

    @Override
    public OAuthApplicationInfo updateApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
        OAuthApplicationInfo oAuthApplicationInfo = oAuthAppRequest.getOAuthApplicationInfo();
        // We have to send the client id with the update request.
        String clientId = oAuthApplicationInfo.getClientId();
        if (log.isDebugEnabled()) {
            log.debug(String.format("Updating oAuth application in NetIQ authorization server for the client " +
                    "id %s.", clientId));
        }
        updateNamAccessToken(oAuthApplicationInfo);
        String updateEndpoint = clientEndpoint + NAMConstants.URL_RESOURCE_SEPERATOR + clientId;

        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        BufferedReader reader = null;
        JSONObject params = getApplication(clientId);
        if (StringUtils.isNotEmpty(clientId)) {
            params.put(NAMConstants.CLIENT_ID, clientId);
        }
        try {
            // Create the JSON Payload that should be sent to OAuth Server.
            createPayloadFromOAuthAppInfo(oAuthApplicationInfo, params);
            HttpPost httpPost = new HttpPost(updateEndpoint);
            httpPost.setEntity(new StringEntity(params.toJSONString(), ContentType.APPLICATION_JSON));
            httpPost.setHeader(NAMConstants.CONTENT_TYPE, NAMConstants.APPLICATION_JSON);
            httpPost.setHeader(NAMConstants.AUTHORIZATION, NAMConstants.BEARER + accessToken);
            HttpResponse response = httpClient.execute(httpPost);
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
                    handleException("Response body is empty for the update application request. Hence can not return " +
                            "oAuthApplicationInfo.");
                }
            } else {
                handleException(String.format("Error occurred when updating the client with client id %s." +
                                " Response: %s. Received status code : %s.",
                        clientId, responseObject.toJSONString(), statusCode));
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
            log.debug(String.format("Deleting the OAuth application from NetIQ authorization server for the client id" +
                    " %s.", clientId));
        }
        updateNamAccessToken(null);
        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        String deleteEndpoint = clientEndpoint + NAMConstants.URL_RESOURCE_SEPERATOR + clientId;

        HttpDelete httpDelete = new HttpDelete(deleteEndpoint);
        httpDelete.setHeader(NAMConstants.AUTHORIZATION, NAMConstants.BEARER + accessToken);
        BufferedReader reader = null;
        try {
            HttpResponse response = httpClient.execute(httpDelete);
            int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode == HttpStatus.SC_OK) {
                log.info(String.format("OAuth application for the client id %s has been successfully deleted.",
                        clientId));
            } else {
                HttpEntity entity = response.getEntity();
                if (entity == null) {
                    handleException(String.format("Could not read http entity for response %s while deleting " +
                            "application for client id %s ", response, clientId));
                }
                reader = new BufferedReader(new InputStreamReader(entity.getContent(),
                        NAMConstants.UTF_8));
                JSONObject responseObject = getParsedObjectByReader(reader);
                handleException(String.format("Problem occurred while deleting OAuth application for the client id" +
                                " %s. Response: %s. Response status code: %s",
                        clientId, responseObject.toJSONString(), statusCode));
            }

        } catch (IOException e) {
            handleException(String.format("Error occurred when reading response body while deleting OAuth application" +
                    " for %s.", clientId), e);
        } catch (ParseException e) {
            handleException(String.format("Error occurred when parsing response while deleting OAuth application" +
                    " for %s.", clientId), e);
        } finally {
            closeResources(reader, httpClient);
        }
    }

    @Override
    public OAuthApplicationInfo retrieveApplication(String clientId) throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Retrieving the OAuth application from NetIQ authorization server for the " +
                    "client id %s.", clientId));
        }

        updateNamAccessToken(null);
        JSONObject responseJSON = getApplication(clientId);

        if (responseJSON == null) {
            handleException(String.format("Failed to retrieve application for client id %s.", clientId));
        }

        return createOAuthAppInfoFromResponse(responseJSON);
    }

    @Override
    public AccessTokenInfo getNewApplicationAccessToken(AccessTokenRequest accessTokenRequest)
            throws APIManagementException {
        String clientId = accessTokenRequest.getClientId();
        if (log.isDebugEnabled()) {
            log.debug(String.format("Retrieving the OAuth application from NetIQ authorization server for the " +
                    "client id %s.", clientId));
        }
        AccessTokenInfo tokenInfo = new AccessTokenInfo();
        String grantType = accessTokenRequest.getGrantType();

        String clientSecret = (String) getApplication(clientId).get(NAMConstants.CLIENT_SECRET);

        if (StringUtils.isEmpty(clientId)) {
            handleException("Mandatory parameter " + NAMConstants.CLIENT_SECRET + " is missing while requesting " +
                    "for a new application access token.");
        }

        if (log.isDebugEnabled()) {
            log.debug(String.format("Getting new client access token from authorization server for the client id %s.",
                    clientId));
        }

        List<NameValuePair> parameters = new ArrayList<>();
        if (grantType == null) {
            grantType = NAMConstants.PASSWORD;
        }
        parameters.add(new BasicNameValuePair(NAMConstants.GRANT_TYPE, grantType));

        String scopeString = convertToString(accessTokenRequest.getScope());
        if (StringUtils.isEmpty(scopeString)) {
            parameters.add(new BasicNameValuePair(NAMConstants.SCOPE, NAMConstants.DEFAULT_SCOPE));
        } else {
            parameters.add(new BasicNameValuePair(NAMConstants.SCOPE, scopeString));
        }

        parameters.add(new BasicNameValuePair(NAMConstants.CLIENT_ID, clientId));
        parameters.add(new BasicNameValuePair(NAMConstants.CLIENT_SECRET, clientSecret));
        parameters.add(new BasicNameValuePair(NAMConstants.USERNAME, username));
        parameters.add(new BasicNameValuePair(NAMConstants.PASSWORD, password));


        JSONObject responseJSON = getAccessTokenWithClientCredentials(clientId, parameters);
        if (responseJSON != null) {
            updateTokenInfo(tokenInfo, responseJSON);
            if (log.isDebugEnabled()) {
                log.debug(String.format("OAuth token has been successfully validated for the client id %s.",
                        clientId));
            }
            return tokenInfo;
        } else {
            tokenInfo.setTokenValid(false);
            tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_INVALID_CREDENTIALS);
            if (log.isDebugEnabled()) {
                log.debug(String.format("OAuth token validation failed for the client id %s.", clientId));
            }
        }
        return tokenInfo;
    }

    @Override
    public String getNewApplicationConsumerSecret(AccessTokenRequest tokenRequest) throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Getting a new client secret for the app with client id %s",
                    tokenRequest.getClientId()));
        }
        return getClientSecret(tokenRequest.getClientId());
    }

    @Override
    public AccessTokenInfo getTokenMetaData(String accessToken) throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Getting metadata of the access token : %s", accessToken));
        }
        JSONObject jsonResponse = doValidateAccessTokenRequest(accessToken);
        AccessTokenInfo tokenInfo = new AccessTokenInfo();

        if (jsonResponse == null) {
            log.error(String.format("Invalid token %s.", accessToken));
            tokenInfo.setTokenValid(false);
            tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_INVALID_CREDENTIALS);
            return tokenInfo;
        }

        String userId = (String) jsonResponse.get(NAMConstants.USER_ID);
        Long expiresIn = (Long) jsonResponse.get(NAMConstants.EXPIRES_IN);
        JSONArray scopeList = (JSONArray) jsonResponse.get(NAMConstants.SCOPE);
        String audience = (String) jsonResponse.get(NAMConstants.AUDIENCE);
        String tokenId = (String) jsonResponse.get(NAMConstants.TOKEN_ID);
        String issuer = (String) jsonResponse.get(NAMConstants.ISSUER);

        if (expiresIn == null) {
            handleException("Mandatory parameter " + NAMConstants.EXPIRES_IN + " is missing in the response " +
                    "when validating token.");
        }

        if (scopeList == null) {
            handleException("Mandatory parameter " + NAMConstants.SCOPE + " is missing in the response " +
                    "when validating token.");
        }

        if (StringUtils.isEmpty(userId)) {
            handleException("Mandatory parameter " + NAMConstants.USER_ID + " is missing in the response when" +
                    " validating token.");
        }

        if (StringUtils.isEmpty(audience)) {
            handleException("Mandatory parameter " + NAMConstants.AUDIENCE + " is missing in the response " +
                    "when validating token.");
        }

        tokenInfo.setConsumerKey(audience);
        tokenInfo.setEndUserName(userId);
        tokenInfo.setValidityPeriod(expiresIn * 1000);
        if (expiresIn > 0) {
            tokenInfo.setTokenValid(true);
        }
        tokenInfo.setIssuedTime(System.currentTimeMillis());

        tokenInfo.setScope((String[]) scopeList.stream().toArray(String[]::new));

        if (!StringUtils.isEmpty(tokenId)) {
            tokenInfo.addParameter(NAMConstants.TOKEN_ID, tokenId);
        }

        if (!StringUtils.isEmpty(issuer)) {
            tokenInfo.addParameter(NAMConstants.ISSUER, issuer);
        }
        return tokenInfo;
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

    @Override
    public Map<String, Set<Scope>> getScopesForAPIS(String s) throws APIManagementException {
        return null;
    }

    private OAuthApplicationInfo createApplication(OAuthApplicationInfo oAuthApplicationInfo)
            throws APIManagementException {
        String[] scope = ((String) oAuthApplicationInfo.getParameter(NAMConstants.TOKEN_SCOPE))
                .split(NAMConstants.INFO_SCOPE_SEPARATOR);
        Object tokenGrantType = oAuthApplicationInfo.getParameter(NAMConstants.INFO_TOKEN_INFO);
        String tokenType = oAuthApplicationInfo.getTokenType();

        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        JSONObject params = new JSONObject();
        createPayloadFromOAuthAppInfo(oAuthApplicationInfo, params);

        HttpPost httpPost = new HttpPost(clientEndpoint);
        try {
            httpPost.setHeader(NAMConstants.CONTENT_TYPE, NAMConstants.APPLICATION_JSON);
            httpPost.setHeader(NAMConstants.AUTHORIZATION, NAMConstants.BEARER + accessToken);
            httpPost.setEntity(new StringEntity(params.toJSONString(), ContentType.APPLICATION_JSON));

            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                handleException(String.format(NAMConstants.STRING_FORMAT,
                        NAMConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY, response));
            }

            BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), NAMConstants.UTF_8));
            JSONObject responseObject = getParsedObjectByReader(reader);

            if (HttpStatus.SC_CREATED == statusCode) {
                if (responseObject != null) {
                    oAuthApplicationInfo = createOAuthAppInfoFromResponse(responseObject);
                    if (scope != null) {
                        oAuthApplicationInfo.addParameter(NAMConstants.TOKEN_SCOPE, scope);
                    }
                    if (tokenGrantType != null) {
                        oAuthApplicationInfo.addParameter(NAMConstants.INFO_TOKEN_GRANT_TYPE, tokenGrantType);
                    }
                    oAuthApplicationInfo.setTokenType(tokenType);
                    return oAuthApplicationInfo;
                }
            } else {
                handleException(String.format("Error occurred while registering the new oAuth application in NetIQ " +
                                "access manager. Response : %s. Response status code : %s",
                        responseObject.toJSONString(), statusCode));
            }

        } catch (UnsupportedEncodingException e) {
            handleException(String.format("Unsupported encoding method has been used when creating a new oAuth " +
                    "application for %s.", oAuthApplicationInfo.getClientId()), e);
        } catch (ClientProtocolException e) {
            throw new APIManagementException(String.format("Error occured while sending an http request for creating " +
                    "a new oAuth application for %s", oAuthApplicationInfo.getClientId()), e);
        } catch (IOException e) {
            handleException(String.format("Error occurred while reading response body when creating a client " +
                    "application for %s.", oAuthApplicationInfo.getClientId()), e);
        } catch (ParseException e) {
            handleException(String.format("Error occurred while parsing response when creating a client application " +
                    "for %s.", oAuthApplicationInfo.getClientId()), e);
        }
        return null;
    }

    /**
     * This method executes the retrieve oAuth application request.
     *
     * @param clientId client id assosiated with the application which needs to be retrieved
     * @return response body of retrieve application request
     * @throws APIManagementException
     */
    private JSONObject getApplication(String clientId) throws APIManagementException {
        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        String registrationEndpoint = clientEndpoint + NAMConstants.URL_RESOURCE_SEPERATOR + clientId;

        BufferedReader reader = null;
        try {
            HttpGet request = new HttpGet(registrationEndpoint);
            request.addHeader(NAMConstants.AUTHORIZATION, NAMConstants.BEARER + accessToken);
            HttpResponse response = httpClient.execute(request);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                handleException(String.format(NAMConstants.STRING_FORMAT,
                        NAMConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY, response));
            }
            reader = new BufferedReader(new InputStreamReader(entity.getContent(), NAMConstants.UTF_8));

            JSONParser parser = new JSONParser();
            Object responseJSON = parser.parse(reader);

            if (statusCode == HttpStatus.SC_OK) {
                return (JSONObject) responseJSON;
            } else {
                handleException(String.format("Error occurred while retrieving oAuth application for consumer " +
                        "key %s. Response: %s, Response Status code: %s",
                        clientId, ((JSONObject) responseJSON).toJSONString(), response.getStatusLine()));
            }
        } catch (ParseException e) {
            handleException(String.format("Error occurred while parsing response when retrieving oAuth application " +
                    "for %s.", clientId), e);
        } catch (IOException e) {
            handleException(String.format("Error while reading response body when retrieving oAuth application of %s.",
                    clientId), e);
        } finally {
            closeResources(reader, httpClient);
        }
        return null;
    }

    /**
     * This method retrieves the oAuth application for the given client id and extracts its client sercret.
     *
     * @param clientId client id which associated with the applicatiion of which the client secret is needed
     * @return client sercret of the application that has the provided client id
     * @throws APIManagementException
     */
    private String getClientSecret(String clientId) throws APIManagementException {
        JSONObject application = getApplication(clientId);
        if (application == null) {
            handleException(String.format("Retrieving applicaiton for client %s failed.", clientId));
        }

        String clientSecret = (String) application.get(NAMConstants.CLIENT_SECRET);
        if (StringUtils.isEmpty(clientId)) {
            handleException("Failed to retrieve client secret for the client " + clientId);
        }
        return clientSecret;
    }

    /**
     * This method initiates validating the access token and updating it if necessary
     *
     * @param info OAuthApplicationInfo of the application, which is related to the operations that require
     *             access token
     * @throws APIManagementException
     */
    private void updateNamAccessToken(OAuthApplicationInfo info) throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Validating and updating the existing access token for client %s", namAppClientId));
        }

        if (accessToken == null || isTokenExpired()) {
            JSONObject response = getAccessTokenWithPassword();
            validityPeriod = (Long) response.get(NAMConstants.EXPIRES_IN);
            accessTokenIssuedTime = System.currentTimeMillis();
            String token = (String) response.get(NAMConstants.ACCESS_TOKEN);
            if (StringUtils.isEmpty(token)) {
                handleException("Failed to get a new access token for " + namAppClientId);
            }
            this.accessToken = token;
        }
    }


    /**
     * This method validates the given access token by calling /tokenInfo endpoint of NetIQ Access Manager.
     *
     * @param accessToken Access token which needs to be validated.
     * @return response body for the validation request as a JSONObject
     * @throws APIManagementException
     */
    private JSONObject doValidateAccessTokenRequest(String accessToken) throws APIManagementException {
        CloseableHttpClient httpClient = HttpClientBuilder.create().build();

        HttpGet httpGet = new HttpGet(tokenInfoEndpoint);
        httpGet.setHeader(NAMConstants.AUTHORIZATION, NAMConstants.BEARER + accessToken);
        BufferedReader reader;
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
                return getParsedObjectByReader(reader);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Status code " + statusCode + " received when trying to get token metadata.");
                }
            }
        } catch (IOException e) {
            handleException("Error occurred when reading the response while getting token meta data.", e);
        } catch (ParseException e) {
            handleException("Error occurred when parsing response while getting token meta data.", e);
        }
        return null;
    }

    /**
     * This method generates and populates an OAuthApplicationInfo object from the response of oAuth application
     * creation request.
     *
     * @param response Response received for the application creation request
     * @return an OAuthApplicationInfo instance which needs to be returned after an oAuth applciation is created
     * @throws APIManagementException
     */
    private OAuthApplicationInfo createOAuthAppInfoFromResponse(JSONObject response)
            throws APIManagementException {

        OAuthApplicationInfo appInfo = new OAuthApplicationInfo();

        String clientId = (String) response.get(NAMConstants.CLIENT_ID);
        String clientName = (String) response.get(NAMConstants.CLIENT_NAME);
        String clientSecret = (String) response.get(NAMConstants.CLIENT_SECRET);

        if (StringUtils.isEmpty(clientId)) {
            handleException(String.format("Mandatory parameter %s is empty in the response %s.",
                    NAMConstants.CLIENT_ID, response.toJSONString()));
        }
        appInfo.setClientId(clientId);

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

        JSONArray grantTypes = (JSONArray) response.get(NAMConstants.GRANT_TYPES);
        StringBuilder types = new StringBuilder();
        for (Object type : grantTypes) {
            types.append(type).append(NAMConstants.NAM_GRANT_TYPE_SEPARATOR);
        }
        appInfo.addParameter(NAMConstants.GRANT_TYPES, types.toString());
        return appInfo;
    }

    /**
     * This method is used to create and throw an APIManagerException for a given error message
     * @param msg error message which needs to be included in the API Manager Exception
     * @throws APIManagementException
     */
    private static void handleException(String msg) throws APIManagementException {
        log.error(msg);
        throw new APIManagementException(msg);
    }

    /**
     * This method generates the body of the applicatoin creation request for a particular oAuth
     * application, in UrlEncoded format.
     *
     * @param appInfo oAuthApplicationInfo of the application that is going to be created
     * @param params a list of name-value pairs which should be included in the reuqest body
     * @return a UrlEncodedFormEntity which needs to be included as the application creation request
     * @throws APIManagementException
     */
    private void createPayloadFromOAuthAppInfo(OAuthApplicationInfo appInfo,
                                               JSONObject params) throws APIManagementException {
        String clientId = appInfo.getClientId();
        if (log.isDebugEnabled()) {
            log.debug(String.format("Creating payload of OAuth application creation request for client id %s.",
                    clientId));
        }

        String keyType = (String) appInfo.getParameter(NAMConstants.KEY_TYPE);
        String clientName = appInfo.getClientName() + '_' + keyType;
        if (StringUtils.isEmpty(clientName)) {
            handleException("Mandatory parameter " + NAMConstants.CLIENT_NAME + " is missing.");
        }
        params.put(NAMConstants.CLIENT_NAME, clientName);

        if (!StringUtils.isEmpty(clientId)) {
            params.put(NAMConstants.CLIENT_ID, clientId);
        }

        String redirectionUri = appInfo.getCallBackURL();
        JSONArray jsonArray = new JSONArray();
        if (!StringUtils.isEmpty(redirectionUri)) {
            Collections.addAll(jsonArray, redirectionUri.split(NAMConstants.URI_SEPARATOR));
            params.put(NAMConstants.REDIRECT_URIS, jsonArray);
        } else {
            Collections.addAll(jsonArray, NAMConstants.DEFAULT_REDIRECT_URI.split(NAMConstants.URI_SEPARATOR));
            params.put(NAMConstants.REDIRECT_URIS, jsonArray);
        }

        String grantTypes = (String) appInfo.getParameter(NAMConstants.GRANT_TYPES);
        if (grantTypes != null) {
            JSONArray grantTypeList = new JSONArray();
            Collections.addAll(grantTypeList, grantTypes.split(NAMConstants.INFO_GRANT_TYPE_SEPARATOR));
            params.put(NAMConstants.GRANT_TYPES, grantTypeList);
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
                params.put(NAMConstants.APPLICATION_TYPE, applicationType);
            }

            String responseTypes = (String) jsonObject.get(NAMConstants.RESPONSE_TYPES);
            JSONArray types = new JSONArray();
            if (!StringUtils.isEmpty(responseTypes)) {
                params.put(NAMConstants.RESPONSE_TYPES, responseTypes);
            }  else {
                Collections.addAll(types, NAMConstants.DEFAULT_RESPONSE_TYPE.split(NAMConstants.URI_SEPARATOR));
                params.put(NAMConstants.RESPONSE_TYPES, types);
            }

            String alwaysIssueNewRefreshToken = (String) jsonObject.get(NAMConstants.ALWAYS_ISSUE_NEW_REFRESH_TOKEN);
            if (!StringUtils.isEmpty(alwaysIssueNewRefreshToken)) {
                params.put(NAMConstants.ALWAYS_ISSUE_NEW_REFRESH_TOKEN, alwaysIssueNewRefreshToken);
            }

            String authzCodeTTL = (String) jsonObject.get(NAMConstants.AUTH_CODE_TTL);
            if (!StringUtils.isEmpty(authzCodeTTL)) {
                params.put(NAMConstants.AUTH_CODE_TTL, authzCodeTTL);
            }

            String accessTokenTTL = (String) jsonObject.get(NAMConstants.ACCESS_TOKEN_TTL);
            if (!StringUtils.isEmpty(accessTokenTTL)) {
                params.put(NAMConstants.ACCESS_TOKEN_TTL, accessTokenTTL);
            }

            String refreshTokenTTL = (String) jsonObject.get(NAMConstants.REFRESH_TOKEN_TTL);
            if (!StringUtils.isEmpty(refreshTokenTTL)) {
                params.put(NAMConstants.REFRESH_TOKEN_TTL, refreshTokenTTL);
            }

            String corsdomains = (String) jsonObject.get(NAMConstants.CORS_DOMAINS);
            if (!StringUtils.isEmpty(corsdomains)) {
                params.put(NAMConstants.CORS_DOMAINS, corsdomains);
            }

            String logoUri = (String) jsonObject.get(NAMConstants.LOGO_URI);
            if (!StringUtils.isEmpty(logoUri)) {
                params.put(NAMConstants.LOGO_URI, logoUri);
            }

            String policyUri = (String) jsonObject.get(NAMConstants.POLICY_URI);
            if (!StringUtils.isEmpty(policyUri)) {
                params.put(NAMConstants.POLICY_URI, policyUri);
            }

            String tosUri = (String) jsonObject.get(NAMConstants.TOS_URI);
            if (!StringUtils.isEmpty(tosUri)) {
                params.put(NAMConstants.TOS_URI, tosUri);
            }

            String contacts = (String) jsonObject.get(NAMConstants.CONTACTS);
            if (!StringUtils.isEmpty(contacts)) {
                params.put(NAMConstants.CONTACTS, contacts);
            }

            String jwksUri = (String) jsonObject.get(NAMConstants.JWKS_URI);
            if (!StringUtils.isEmpty(jwksUri)) {
                params.put(NAMConstants.JWKS_URI, jwksUri);
            }

            String idTokenSignedResponseAlg = (String) jsonObject.get(NAMConstants.ID_TOKEN_SIGNED_RESPONSE_ALG);
            if (!StringUtils.isEmpty(idTokenSignedResponseAlg)) {
                params.put(NAMConstants.ID_TOKEN_SIGNED_RESPONSE_ALG, idTokenSignedResponseAlg);
            }

            String idTokenEncryptedResponseAlg =
                    (String) jsonObject.get(NAMConstants.ID_TOKEN_ENCRYPTED_RESPONSE_ALG);
            if (!StringUtils.isEmpty(idTokenEncryptedResponseAlg)) {
                params.put(NAMConstants.ID_TOKEN_ENCRYPTED_RESPONSE_ALG, idTokenEncryptedResponseAlg);
            }

            String idTokenEnctryptedResponseEnc =
                    (String) jsonObject.get(NAMConstants.ID_TOKEN_ENCRYPTED_RESPONSE_ENC);
            if (!StringUtils.isEmpty(idTokenEnctryptedResponseEnc)) {
                params.put(NAMConstants.ID_TOKEN_ENCRYPTED_RESPONSE_ENC, idTokenEnctryptedResponseEnc);
            }
        }
    }

    /**
     * This method is used to extract the content of a response for an http request, as a JSONObject.
     *
     * @param reader Reader that reads the input stream of the response
     * @return an JSONObject which is generated from the content of the response
     * @throws ParseException
     * @throws IOException
     */
    private JSONObject getParsedObjectByReader(BufferedReader reader) throws ParseException, IOException {
        JSONObject parsedObject = null;
        JSONParser parser = new JSONParser();
        if (reader != null) {
            parsedObject = (JSONObject) parser.parse(reader);
        }
        return parsedObject;
    }

    /**
     * This method is used to close the readers and http clients which are used to call NetIQ access manager
     * endpoints and to read the responses.
     *
     * @param reader BufferedReader instance which needs to be closed
     * @param httpClient HttpClient instance which needs to be closed
     */
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

    /**
     * This method is used to get an access token using client credentials flow.
     * (i.e. using client id and client secret)
     *
     * @param clientId client id of the client for which access token is needed
     * @param parameters name-value pairs that needs to be included in the token request body
     * @return an JSONObject instance which is generated from the response of token request.
     *         This should contain the access token for the given.
     * @throws APIManagementException
     */
    private JSONObject getAccessTokenWithClientCredentials(String clientId, List<NameValuePair> parameters)
            throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Getting a new access token for client %s using client credentials flow.",
                    clientId));
        }

        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        BufferedReader reader = null;
        try {
            HttpPost httpPost = new HttpPost(tokenEndpoint);
            httpPost.setHeader(NAMConstants.CONTENT_TYPE, NAMConstants.APPLICATIN_FORM_URL_ENCODED);
            httpPost.setEntity(new UrlEncodedFormEntity(parameters));
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
                                responseJSON));
                    }
                    return responseJSON;
                }
            } else {
                log.error(String.format("Failed to get accessToken for client id %s. Response: %s. Received status " +
                        "code : ", clientId, responseJSON.toJSONString(), statusCode));
            }
        } catch (UnsupportedEncodingException e) {
            handleException(String.format("Error occurred when encoding while getting a new access token for %s.",
                    clientId), e);
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

    /**
     * This method is used to update a given AccessTokenInfo instance with the values received from a reuqest sent to
     * the token end point of NetIQ Access Manager.
     *
     * @param tokenInfo AccessTokenInfo instance that needs to be updated from the response
     * @param responseJSON JSSONObject instance generated from the response of a token request
     * @return Updated AccessTokenInfo instance
     */
    private AccessTokenInfo updateTokenInfo(AccessTokenInfo tokenInfo, JSONObject responseJSON) {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Update the access token info with JSON response: %s, after getting " +
                    "the new access token.", responseJSON));
        }
        Long expireTime = (Long) responseJSON.get(NAMConstants.EXPIRES_IN);
        if (expireTime == null) {
            tokenInfo.setTokenValid(false);
            tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_INVALID_CREDENTIALS);
            return tokenInfo;
        }

        tokenInfo.setTokenValid(true);
        tokenInfo.setAccessToken((String) responseJSON.get(NAMConstants.ACCESS_TOKEN));
        tokenInfo.setValidityPeriod(expireTime);

        String tokenScopes = (String) responseJSON.get(NAMConstants.SCOPE);
        if (StringUtils.isNotEmpty(tokenScopes)) {
            tokenInfo.setScope(tokenScopes.split(NAMConstants.TOKEN_SCOPE_SPLIT_REGEX));
        }
        return tokenInfo;
    }

    /**
     * This method is used to get an access token using resource owner flow.
     * (i.e. using username and password)
     * This will be used only at the begining to get the access token. After getting the access token for the first
     * time, token endpoint will be called using client id and secret. (using client credentials flow)
     *
     * @return access token received from the NetIQ access manager for the given user credentials.
     * @throws APIManagementException
     */
    private JSONObject getAccessTokenWithPassword() throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Getting a new access token for client %s using resource owner flow.",
                    namAppClientId));
        }

        List<NameValuePair> params = new ArrayList<>();

        params.add(new BasicNameValuePair(NAMConstants.USERNAME, username));
        params.add(new BasicNameValuePair(NAMConstants.PASSWORD, password));
        params.add(new BasicNameValuePair(NAMConstants.CLIENT_ID, namAppClientId));
        params.add(new BasicNameValuePair(NAMConstants.CLIENT_SECRET, namAppClientSecret));
        params.add(new BasicNameValuePair(NAMConstants.GRANT_TYPE, NAMConstants.PASSWORD));
        params.add(new BasicNameValuePair(NAMConstants.SCOPE, NAMConstants.DEFAULT_SCOPE));

        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        HttpPost httpPost = new HttpPost(tokenEndpoint);
        try {
            httpPost.setHeader(NAMConstants.CONTENT_TYPE, NAMConstants.APPLICATIN_FORM_URL_ENCODED);
            httpPost.setEntity(new UrlEncodedFormEntity(params));

            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                handleException(String.format(NAMConstants.STRING_FORMAT,
                        NAMConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY, response));
            }

            BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), NAMConstants.UTF_8));
            JSONObject responseObject = getParsedObjectByReader(reader);

            if (HttpStatus.SC_OK == statusCode) {
                if (responseObject != null) {
                    return responseObject;
                } else {
                    handleException(String.format("Response body does not contain the %s when " +
                                    "getting a new access token while getting a new access token for %s.",
                            NAMConstants.ACCESS_TOKEN, namAppClientId));
                }
            } else {
                handleException(String.format("Error occured while getting a new access token for %s." +
                                "Response : %s. Response status code : %s",
                        namAppClientId, responseObject.toJSONString(), statusCode));
            }

        } catch (UnsupportedEncodingException e) {
            handleException(String.format("Unsupported encoding method has been used getting a new access token for  " +
                    "%s.", namAppClientId), e);
        } catch (ClientProtocolException e) {
            throw new APIManagementException(NAMConstants.ERROR_CLIENT_PROTOCOL, e);
        } catch (IOException e) {
            handleException(String.format("Error occurred while reading response body when getting a new access token" +
                    " for  %s.", namAppClientId), e);
        } catch (ParseException e) {
            handleException(String.format("Error occurred while parsing response when getting a new access token for " +
                    "%s.", namAppClientId), e);
        }
        return null;
    }

    /**
     * This method is used to generate a string from a string array. Each element of the array is separated by a space.
     *
     * @param stringArray an array of string which needs to be convened to a string
     * @return generated string, null if array is null
     */
    private String convertToString(String[] stringArray) {
        if (stringArray != null) {
            StringBuilder sb = new StringBuilder();
            List<String> strList = Arrays.asList(stringArray);
            for (String s : strList) {
                sb.append(s);
                sb.append(NAMConstants.NAM_SCOPE_SEPARATOR);
            }
            return sb.toString().trim();
        }
        return null;
    }

    /**
     * This method is used to generate a string array from the content of a json array.
     *
     * @param jsonArray Json array which needs to be converted to a string array
     * @return Array of string which is generated from the content of given json array
     */
    private String[] generateStringArray(JSONArray jsonArray) {
        if (jsonArray != null) {
            int i = 0;
            String[] array = new String[jsonArray.size()];
            for (Object obj : jsonArray) {
                array[i++] = obj.toString();
            }
        }
        return null;
    }

    /**
     * This method is used to check whether the access token is expired.
     *
     * @return true if the token has been expired, false if it's not
     */
    private boolean isTokenExpired() {
        return System.currentTimeMillis() - accessTokenIssuedTime > validityPeriod ? true : false;
    }
}
