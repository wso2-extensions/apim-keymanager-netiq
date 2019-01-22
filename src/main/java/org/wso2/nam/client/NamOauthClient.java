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
import org.wso2.carbon.apimgt.api.model.Scope;
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
import java.util.UUID;

/**
 * This class contains the key manager implementation for WSO2 APIM considering Net IQ as the access manager.
 */
public class NamOauthClient extends AbstractKeyManager {
    private static final Log log = LogFactory.getLog(NamOauthClient.class);
    private KeyManagerConfiguration configuration;
    private String namInstanceURL;
    private String apiKey;
    private String accessToken;
    private String refreshToken;

    @Override
    public void loadConfiguration(KeyManagerConfiguration keyManagerConfiguration) throws APIManagementException {
        this.configuration = keyManagerConfiguration;
        namInstanceURL = configuration.getParameter(NAMConstants.CONFIG_NAM_INSTANCE_URL);
    }

    @Override
    public OAuthApplicationInfo createApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
        OAuthApplicationInfo oAuthApplicationInfo = oAuthAppRequest.getOAuthApplicationInfo();
        String clientName = oAuthApplicationInfo.getClientName();

        if (log.isDebugEnabled()) {
            log.debug(String.format("Creating an OAuth client in NetIQ authorization server with application name %s",
                    clientName));
        }

        updateAccessToken(oAuthApplicationInfo);

        String[] scope = (String[]) ((String) oAuthApplicationInfo.getParameter(NAMConstants.TOKEN_SCOPE))
                .split(NAMConstants.INFO_SCOPE_SEPERATOR);
        Object tokenGrantType = oAuthApplicationInfo.getParameter(NAMConstants.INFO_TOKEN_INFO);
        String tokenType = oAuthApplicationInfo.getTokenType();

        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        String registrationEndpoint = namInstanceURL + NAMConstants.CLIENT_ENDPOINT;
        List<NameValuePair> params = new ArrayList<NameValuePair>();
        oAuthApplicationInfo.setClientId(UUID.randomUUID().toString());
        UrlEncodedFormEntity urlEncodedFormEntity = createPayloadFromOAuthAppInfo(oAuthApplicationInfo, params);

        HttpPost httpPost = new HttpPost(registrationEndpoint);
        try {
            httpPost.setHeader(NAMConstants.CONTENT_TYPE, NAMConstants.APPLICATIN_FORM_URL_ENCODED);
            httpPost.setHeader(NAMConstants.AUTHORIZATION, NAMConstants.BEARER + accessToken);
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
                    oAuthApplicationInfo = createOAuthAppInfoFromResponse(responseObject,
                            oAuthApplicationInfo.getClientId());
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
                handleException(String.format("Error occured while registering the new oAuth applciation in NetIQ " +
                        "access manager. Response : %s. Received staus code : ", responseObject.toJSONString(),
                        statusCode));
            }

        } catch (UnsupportedEncodingException e) {
            handleException(String.format("Unsupported encoding method has been used when creating a new oAuth " +
                    "application for %s.", oAuthApplicationInfo.getClientId()), e);
        } catch (ClientProtocolException e) {
            throw new APIManagementException(String.format("Error occured while sending an http reqeust for creating " +
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

    @Override
    public OAuthApplicationInfo updateApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
        OAuthApplicationInfo oAuthApplicationInfo = oAuthAppRequest.getOAuthApplicationInfo();
        // We have to send the client id with the update request.
        String clientId = oAuthApplicationInfo.getClientId();
        if (log.isDebugEnabled()) {
            log.debug(String.format("Updating oAuth application in NetIQ authorization server for the consumer " +
                    "key %s.", clientId));
        }
        updateAccessToken(oAuthApplicationInfo);
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
            httpPut.setHeader(NAMConstants.AUTHORIZATION, NAMConstants.BEARER + accessToken);
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
                    return createOAuthAppInfoFromResponse(responseObject, clientId);
                } else {
                    handleException("Response body is empty for the update applicatoin request. Hence can not return " +
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
        updateAccessToken(null);
        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        String deleteEndpoint = namInstanceURL + NAMConstants.CLIENT_ENDPOINT + "/" + clientId;

        HttpDelete httpDelete = new HttpDelete(deleteEndpoint);
        // TODO : how should these requests be authenticated
        httpDelete.setHeader(NAMConstants.AUTHORIZATION, NAMConstants.BEARER + accessToken);
        BufferedReader reader = null;
        try {
            HttpResponse response = httpClient.execute(httpDelete);
            int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode == HttpStatus.SC_NO_CONTENT) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("OAuth applicaiton for the client id %s has been successfully deleted.",
                            clientId));
                }
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
                        " %s. Response : %s. Reveived status code : ",
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
            log.debug(String.format("Retrieving the OAuth applicatoin from NetIQ authorization server for the " +
                    "client id %s.", clientId));
        }

        updateAccessToken(null);
        JSONObject responseJSON = getApplication(clientId);

        if (responseJSON == null) {
            handleException(String.format("Failed to retrieve application for client id %s.", clientId));
        }

        return createOAuthAppInfoFromResponse(responseJSON, clientId);
    }

    @Override
    public AccessTokenInfo getNewApplicationAccessToken(AccessTokenRequest accessTokenRequest)
            throws APIManagementException {
        String clientId = accessTokenRequest.getClientId();
        if (log.isDebugEnabled()) {
            log.debug(String.format("Retrieving the OAuth applicatoin from NetIQ authorization server for the " +
                    "client id %s.", clientId));
        }
        AccessTokenInfo tokenInfo = new AccessTokenInfo();
        String grantType = accessTokenRequest.getGrantType();

        String clientSecret = (String) getApplication(clientId).get(NAMConstants.CLIENT_SECRET);

        revokeAccessToken(clientId, clientSecret, refreshToken);
        if (StringUtils.isEmpty(clientId)) {
            handleException("Mandatory parameter " + NAMConstants.CLIENT_SECRET + " is missing while requesting " +
                    "for a new application acces token.");
        }

        if (log.isDebugEnabled()) {
            log.debug(String.format("Getting new client access token from authorization server for the client id %s.",
                    clientId));
        }

        List<NameValuePair> parameters = new ArrayList<NameValuePair>();
        if (grantType == null) {
            grantType = NAMConstants.CLIENT_CREDENTIALS;
        }
        parameters.add(new BasicNameValuePair(NAMConstants.GRANT_TYPE, grantType));

        String scopeString = convertToString(accessTokenRequest.getScope());
        if (StringUtils.isEmpty(scopeString)) {
            parameters.add(new BasicNameValuePair(NAMConstants.SCOPE, scopeString));
        }

        parameters.add(new BasicNameValuePair(NAMConstants.CLIENT_ID, clientId));
        parameters.add(new BasicNameValuePair(NAMConstants.CLIENT_SECRET, clientSecret));


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
        return getClientSecret(tokenRequest.getClientId());
    }

    @Override
    public AccessTokenInfo getTokenMetaData(String accessToken) throws APIManagementException {
        JSONObject jsonResponse = doValidateAccessTokenRequest(accessToken);
        AccessTokenInfo tokenInfo = new AccessTokenInfo();

        if (jsonResponse == null) {
            log.error(String.format("Invalid token %s.", accessToken));
            tokenInfo.setTokenValid(false);
            tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_INVALID_CREDENTIALS);
            return tokenInfo;
        }
        // handle responses
        String userId = (String) jsonResponse.get(NAMConstants.USER_ID);
        Long expriresIn = (Long) jsonResponse.get(NAMConstants.EXPIRES_IN);
        JSONArray scope = (JSONArray) jsonResponse.get(NAMConstants.SCOPE);
        String audience = (String) jsonResponse.get(NAMConstants.AUDIENCE);
        String tokenId = (String) jsonResponse.get(NAMConstants.TOKEN_ID);
        String issuer = (String) jsonResponse.get(NAMConstants.ISSUER);

        if (expriresIn == null) {
            handleException("Mandatory parameter " + NAMConstants.EXPIRES_IN + " is missing in the response " +
                    "when validating token.");
        }

        if (scope == null) {
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
        tokenInfo.setValidityPeriod(expriresIn * 1000);
        if (scope != null) {
            int i = 0;
            String[] scopes = new String[scope.size()];
            for (Object obj : scope) {
                scopes[i++] = obj.toString();
            }
            tokenInfo.setScope(scopes);
        }

        if (!StringUtils.isEmpty(tokenId)) {
            tokenInfo.addParameter(NAMConstants.TOKEN_ID, tokenId);
        }

        if (!StringUtils.isEmpty(issuer)) {
            tokenInfo.addParameter(NAMConstants.ISSUER, issuer);
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

    @Override
    public Map<String, Set<Scope>> getScopesForAPIS(String s) throws APIManagementException {
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
        String registrationEndpoint = namInstanceURL + NAMConstants.CLIENT_ENDPOINT;

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
            Object responseJSON;

            if (statusCode == HttpStatus.SC_OK) {
                JSONParser parser = new JSONParser();
                responseJSON = parser.parse(reader);
                return (JSONObject) responseJSON;
            } else {
                handleException(String.format("Error occurred while retrieving oAuth application for consumer " +
                        "key %s.", clientId));
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
    private void updateAccessToken(OAuthApplicationInfo info) throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Validating and updating the existing access token."));
        }
        if (accessToken == null || doValidateAccessTokenRequest(accessToken) == null) {
            String token = getAccessTokenWithPassword(info);
            if (StringUtils.isEmpty(token)) {
                handleException("Failed to get a new access token for " + info.getClientId());
            }
            this.accessToken = token;
        }
    }

    /**
     * This method init
     * @param accessToken
     * @return
     * @throws APIManagementException
     */
    private boolean isAccessTokenValid(String accessToken) throws APIManagementException {
        JSONObject response = doValidateAccessTokenRequest(accessToken);
        if (response != null) {
            return true;
        }
        return false;
    }

    /**
     * This method validates the given access token by calling /tokenInfo endpoint of NetIQ Access Manager.
     *
     * @param accessToken Access token which needs to be validated.
     * @return response body for the validation request as a JSONObject
     * @throws APIManagementException
     */
    private JSONObject doValidateAccessTokenRequest(String accessToken) throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Getting access token metadata from the authorization server."));
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
     * @param clientId Cliend id of the application which was created
     * @return an OAuthApplicationInfo instance which needs to be returned after an oAuth applciation is created
     * @throws APIManagementException
     */
    private OAuthApplicationInfo createOAuthAppInfoFromResponse(JSONObject response, String clientId)
            throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Retrieving the OAuth applicatoin from NetIQ authorization server for the " +
                    "client id %s.", clientId));
        }
        OAuthApplicationInfo appInfo = new OAuthApplicationInfo();

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
        if (response != null) {
            StringBuilder types = new StringBuilder();
            for (Object type : grantTypes) {
                types.append(type).append(NAMConstants.NAM_GRANT_TYPE_SEPERATOR);
            }
            appInfo.addParameter(NAMConstants.GRANT_TYPES, types.toString());
        }
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
    private UrlEncodedFormEntity createPayloadFromOAuthAppInfo(OAuthApplicationInfo appInfo,
                                                  List<NameValuePair> params) throws APIManagementException {
        String clientId = appInfo.getClientId();
        if (log.isDebugEnabled()) {
            log.debug(String.format("Creating payload of OAuth application creation request for client id %s.",
                    clientId));
        }

        String clientName = appInfo.getClientName();
        if (StringUtils.isEmpty(clientName)) {
            handleException("Mandatory parameter " + NAMConstants.CLIENT_NAME + " is missing.");
        }
        params.add(new BasicNameValuePair(NAMConstants.CLIENT_NAME, clientName));

        if (StringUtils.isEmpty(clientId)) {
            params.add(new BasicNameValuePair(NAMConstants.CLIENT_ID, clientId));
        }

        String redirectionUri = appInfo.getCallBackURL();
        if (!StringUtils.isEmpty(redirectionUri)) {
            params.add(new BasicNameValuePair(NAMConstants.REDIRECTION_URI, redirectionUri));
        }

        String grantTypes = (String) appInfo.getParameter(NAMConstants.GRANT_TYPES);
        if (grantTypes != null) {
            JSONArray jsonArray = new JSONArray();
            Collections.addAll(jsonArray, grantTypes.split(NAMConstants.INFO_GRANT_TYPE_SEPERATOR));
            params.add(new BasicNameValuePair(NAMConstants.GRANT_TYPES, jsonArray.toJSONString()));
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
                params.add(new BasicNameValuePair(NAMConstants.ALWAYS_ISSUE_NEW_REFRESH_TOKEN,
                        alwaysIssueNewRefreshToken));
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

    /**
     * This method calls the revoke endpoint of the NetIQ access maanger to revoke a given token.
     *
     * @param clientSecret client sercret which needs to authenticate the request
     * @param refreshToken refresh token for the revoke operation
     * @throws APIManagementException
     */
    private void revokeAccessToken(String clientId, String clientSecret, String refreshToken)
            throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Revoking the application access token for client id %s.", clientId));
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

            HttpResponse response = httpClient.execute(httpPost);
            // TODO: 16/11/18 Handle response (error code)
            int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode == HttpStatus.SC_OK) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Application accessToken for client id %s has been successfully " +
                            "revoked.", clientId));
                }
            } else {
                handleException(String.format("Problem occurred while revoking the access token for client id %s. " +
                                "Status code %d was received for the revoke request.", clientId, statusCode));
            }
        } catch (UnsupportedEncodingException e) {
            handleException(String.format("Unsupported encoding has been used while revoking token for %s.",
                    clientId), e);
        } catch (ClientProtocolException e) {
            handleException(String.format("HTTP error has occurred when sending request to OAuth Provider while " +
                    "revoking token for %s.", clientId), e);
        } catch (IOException e) {
            handleException(String.format("Error occured when reading response body while revoking token for %s.",
                    clientId), e);
        } finally {
            closeResources(null, httpClient);
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
     * This medthod is used to close the readers and http clients which are used to call NetIQ access manager
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
            log.debug(String.format("Getting a new access token using client credentials flow."));
        }

        CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        BufferedReader reader = null;

        try {
            HttpPost httpPost = new HttpPost(namInstanceURL + NAMConstants.TOKEN_ENDPOINT);
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
                                responseJSON.toJSONString()));
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
                    "new access token.", responseJSON));
        }
        Long expireTime = (Long) responseJSON.get(NAMConstants.EXPIRES_IN);
        if (expireTime == null) {
            tokenInfo.setTokenValid(false);
            tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_INVALID_CREDENTIALS);
            return tokenInfo;
        }

        tokenInfo.setTokenValid(true);
        tokenInfo.setAccessToken((String) responseJSON.get(NAMConstants.ACCESS_TOKEN));
        tokenInfo.setValidityPeriod(expireTime * 1000);

        String tokenScopes = (String) responseJSON.get(NAMConstants.SCOPE);
        if (StringUtils.isNotEmpty(tokenScopes)) {
            tokenInfo.setScope(tokenScopes.split("\\s+"));
        }
        return tokenInfo;
    }

    /**
     * This method is used to get an access token using resource owner flow.
     * (i.e. using username and password)
     * This will be used only at the begining to get the access token. After getting the access token for the first
     * time, token endpoint will be called using client id and secret. (using client credentials flow)
     *
     * @param info an OAuthApplicationInfo instance which cotains the info related to the oAuth applicaiton for which
     *            the access token should be generated.
     * @return access token received from the NetIQ access manager for the given user credentials.
     * @throws APIManagementException
     */
    private String getAccessTokenWithPassword(OAuthApplicationInfo info) throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Getting a new access token using resource owner flow."));
        }

        List<NameValuePair> params = new ArrayList<NameValuePair>();
        String username = configuration.getParameter(NAMConstants.CONFIG_USERNAME);
        String password = configuration.getParameter(NAMConstants.CONFIG_PASSWORD);
        String clientId = configuration.getParameter(NAMConstants.CONFIG_CLIENT_ID);
        String clientSecret = configuration.getParameter(NAMConstants.CONFIG_CLIENT_SECRET);
        String grantType = NAMConstants.PASSWORD;
        String registrationEndpoint = namInstanceURL + NAMConstants.TOKEN_ENDPOINT;
        String scope = null;
        if (info != null) {
            scope = (String) info.getParameter(NAMConstants.SCOPE);
        }

        if (StringUtils.isEmpty(username)) {
            handleException(String.format("Mandotary parameter %s is missing in configuration.",
                    NAMConstants.CONFIG_USERNAME));
        }
        params.add(new BasicNameValuePair(NAMConstants.USERNAME, username));

        if (StringUtils.isEmpty(password)) {
            handleException(String.format("Mandotary parameter %s is missing in configuration.",
                    NAMConstants.CONFIG_PASSWORD));
        }
        params.add(new BasicNameValuePair(NAMConstants.PASSWORD, password));

        if (StringUtils.isEmpty(clientId)) {
            handleException(String.format("Mandatory parameter %s is missing when getting a new access token",
                    NAMConstants.CONFIG_CLIENT_ID));
        }
        params.add(new BasicNameValuePair(NAMConstants.CLIENT_ID, clientId));

        if (StringUtils.isEmpty(clientSecret)) {
            handleException(String.format("Mandatory parameter %s is missing when getting a new access token",
                    NAMConstants.CONFIG_CLIENT_SECRET));
        }
        params.add(new BasicNameValuePair(NAMConstants.CLIENT_SECRET, clientSecret));

        if (StringUtils.isEmpty(grantType)) {
            handleException(String.format("Mandatory parameter %s is missing when getting a new access token",
                    NAMConstants.GRANT_TYPE));
        }
        params.add(new BasicNameValuePair(NAMConstants.GRANT_TYPE, grantType));

       CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        HttpPost httpPost = new HttpPost(registrationEndpoint);
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
                    refreshToken = (String) responseObject.get(NAMConstants.REFRESH_TOKEN);
                    return (String) responseObject.get(NAMConstants.ACCESS_TOKEN);
                } else {
                    handleException(String.format("Response body does not contain the %s when " +
                                    "getting a new access token while getting a new access token for %s.",
                            NAMConstants.ACCESS_TOKEN, clientId));
                }
            } else {
                handleException(String.format("Error occured while getting a new access token for %s." +
                        "Response : %s. Received status code : %s",
                        clientId, responseObject.toJSONString(), statusCode));
            }

        } catch (UnsupportedEncodingException e) {
            handleException(String.format("Unsupported encoding method has been used getting a new access token for  " +
                    "%s.", clientId), e);
        } catch (ClientProtocolException e) {
            throw new APIManagementException(NAMConstants.ERROR_CLIENT_PROTOCOL, e);
        } catch (IOException e) {
            handleException(String.format("Error occurred while reading response body when getting a new access token" +
                    " for  %s.", clientId), e);
        } catch (ParseException e) {
            handleException(String.format("Error occurred while parsing response when getting a new access token for " +
                    "%s.", clientId), e);
        }
        return null;
    }

    /**
     * This method is used to generate a string from a string array. Each element of the array is seperated by a space.
     *
     * @param stringArray an array of string which needs to be convered to a string
     * @return generated string, null if array is null
     */
    private String convertToString(String[] stringArray) {
        if (stringArray != null) {
            StringBuilder sb = new StringBuilder();
            List<String> strList = Arrays.asList(stringArray);
            for (String s : strList) {
                sb.append(s);
                sb.append(NAMConstants.NAM_SCOPE_SEPERATOR);
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
     * This method is used to encode client credentials in Base64 format.
     *
     * @param clientId client id which needs to be included in the auth header of the request
     * @param clientSecret client secret which needs to be included in the auth header of the request
     * @return encoded string which can be used in the auth header in the http request
     * @throws APIManagementException
     */
    private static String getEncodedCredentials(String clientId, String clientSecret) throws APIManagementException {
        try {
            return Base64.getEncoder().encodeToString((clientId + ":" + clientSecret)
                    .getBytes(NAMConstants.UTF_8));
        } catch (UnsupportedEncodingException e) {
            throw new APIManagementException(NAMConstants.ERROR_ENCODING_METHOD_NOT_SUPPORTED, e);
        }
    }
}
