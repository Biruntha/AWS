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
package org.wso2.carbon.user.aws.util;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.aws.AWSConstants;
import org.wso2.carbon.user.core.UserStoreException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.Map;
import java.util.TreeMap;

/**
 * Provides REST API operations to connect with Amazon Cloud Directory.
 */
public class AWSRestApiActions {

    private static final Log log = LogFactory.getLog(AWSRestApiActions.class);
    private String hostHeader;
    private String region;
    private String apiVersion;
    private String accessKeyID;
    private String secretAccessKey;

    public AWSRestApiActions(RealmConfiguration realmConfig) {

        region = realmConfig.getUserStoreProperty(AWSConstants.REGION);
        apiVersion = realmConfig.getUserStoreProperty(AWSConstants.API_VERSION);
        hostHeader = AWSConstants.SERVICE + "." + region + AWSConstants.AMAZON_AWS_COM;
        accessKeyID = realmConfig.getUserStoreProperty(AWSConstants.ACCESS_KEY_ID);
        secretAccessKey = realmConfig.getUserStoreProperty(AWSConstants.SECRET_ACCESS_KEY);
    }

    /**
     * Lists directories created within an AWS account.
     *
     * @return List of directories.
     * @throws UserStoreException If error occurred.
     */
    public JSONObject listDirectories() throws UserStoreException {

        if (log.isDebugEnabled()) {
            log.debug("Listing all directories in AWS cloud service.");
        }
        String canonicalURI = AWSConstants.AMAZON_CLOUD_DIRECTORY + apiVersion + AWSConstants.LIST_DIRECTORIES;
        TreeMap<String, String> awsHeaders = new TreeMap<>();
        awsHeaders.put(AWSConstants.HOST_HEADER, hostHeader);

        String payload = AWSConstants.PAYLOAD_LIST_DIRECTORIES;
        if (log.isDebugEnabled()) {
            log.debug(String.format("Payload to list directories : %s ", payload));
        }
        AWSV4Auth aWSV4Auth = new AWSV4Auth.Builder(accessKeyID, secretAccessKey)
                .regionName(region)
                .serviceName(AWSConstants.SERVICE)
                .httpMethodName(AWSConstants.HTTP_POST)
                .canonicalURI(canonicalURI)
                .queryParametes(null)
                .awsHeaders(awsHeaders)
                .payload(payload)
                .build();

        HttpPost httpPost = new HttpPost(AWSConstants.HTTPS + hostHeader + canonicalURI);

        /* Get header calculated for request */
        Map<String, String> header = aWSV4Auth.getHeaders();
        for (Map.Entry<String, String> entrySet : header.entrySet()) {
            httpPost.setHeader(entrySet.getKey(), entrySet.getValue());
        }
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
            httpPost.setHeader(AWSConstants.HOST_HEADER, hostHeader);
            httpPost.setEntity(new StringEntity(payload, AWSConstants.UTF_8));
            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to list directories.");
            }
            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                handleException(String.format(AWSConstants.STRING_FORMAT, AWSConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY,
                        response));
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), AWSConstants.UTF_8));
            JSONObject responseObject = getParsedObjectByReader(reader);
            if (statusCode == HttpStatus.SC_OK) {
                return responseObject;
            } else {
                handleException(String.format("Error occured while list directories. " +
                        "Response : %s", responseObject.toJSONString()));
            }
        } catch (ParseException e) {
            handleException(AWSConstants.ERROR_WHILE_PARSING_RESPONSE, e);
        } catch (IOException e) {
            handleException(AWSConstants.ERROR_WHILE_READING_RESPONSE, e);
        }
        return null;
    }

    /**
     * Returns a paginated list of all the outgoing TypedLinkSpecifier information for an object.
     *
     * @param directoryArn The Amazon Resource Name (ARN) of the directory.
     * @param payload      Payload to list OutgoingTypedLinks.
     * @return Returns outgoing typed link specifiers as output.
     * @throws UserStoreException If error occurred.
     */
    public JSONObject listOutgoingTypedLinks(String directoryArn, String payload) throws UserStoreException {

        System.out.println("Inside listOutgoingTypedLinks--------");
        if (log.isDebugEnabled()) {
            log.debug("Getting all the outgoing TypedLinkSpecifier information for an object.");
        }
        String canonicalURI = AWSConstants.AMAZON_CLOUD_DIRECTORY + apiVersion + AWSConstants.LIST_OUTGOING_TYPEDLINK;
        TreeMap<String, String> awsHeaders = new TreeMap<>();
        awsHeaders.put(AWSConstants.HOST_HEADER, hostHeader);
        awsHeaders.put(AWSConstants.PARTITION_HEADER, directoryArn);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Payload to get outgoing TypedLinkSpecifier information : %s ", payload));
        }
        AWSV4Auth aWSV4Auth = new AWSV4Auth.Builder(accessKeyID, secretAccessKey)
                .regionName(region)
                .serviceName(AWSConstants.SERVICE)
                .httpMethodName(AWSConstants.HTTP_POST)
                .canonicalURI(canonicalURI)
                .queryParametes(null)
                .awsHeaders(awsHeaders)
                .payload(payload)
                .build();

        HttpPost httpPost = new HttpPost(AWSConstants.HTTPS + hostHeader + canonicalURI);

        /* Get header calculated for request */
        Map<String, String> header = aWSV4Auth.getHeaders();
        for (Map.Entry<String, String> entrySet : header.entrySet()) {
            httpPost.setHeader(entrySet.getKey(), entrySet.getValue());
        }
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
            httpPost.setHeader(AWSConstants.HOST_HEADER, hostHeader);
            httpPost.setHeader(AWSConstants.PARTITION_HEADER, directoryArn);
            httpPost.setEntity(new StringEntity(payload, AWSConstants.UTF_8));
            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to get outgoing TypedLinkSpecifier information.");
            }
            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                handleException(String.format(AWSConstants.STRING_FORMAT, AWSConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY, response));
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), AWSConstants.UTF_8));
            JSONObject responseObject = getParsedObjectByReader(reader);
            System.out.println("Response Object : " + responseObject.toJSONString());
            if (statusCode == HttpStatus.SC_OK) {
                return responseObject;
            } else {
                handleException(String.format("Error occured while getting outgoing TypedLinkSpecifier. " +
                        "Response : %s", responseObject.toJSONString()));
            }
        } catch (ParseException e) {
            handleException(AWSConstants.ERROR_WHILE_PARSING_RESPONSE, e);
        } catch (IOException e) {
            handleException(AWSConstants.ERROR_WHILE_READING_RESPONSE, e);
        }
        return null;
    }

    /**
     * Returns a paginated list of all the incoming TypedLinkSpecifier information for an object.
     *
     * @param directoryArn The Amazon Resource Name (ARN) of the directory.
     * @param payload      Payload to list IncomingTypedLinks.
     * @return Returns incoming typed link specifiers as output.
     * @throws UserStoreException If error occurred.
     */
    public JSONObject listIncomingTypedLinks(String directoryArn, String payload) throws UserStoreException {

        System.out.println("Inside listIncomingTypedLinks--------");
        if (log.isDebugEnabled()) {
            log.debug("Getting all the incoming TypedLinkSpecifier information for an object.");
        }
        String canonicalURI = AWSConstants.AMAZON_CLOUD_DIRECTORY + apiVersion + AWSConstants.LIST_INCOMING_TYPEDLINK;
        TreeMap<String, String> awsHeaders = new TreeMap<>();
        awsHeaders.put(AWSConstants.HOST_HEADER, hostHeader);
        awsHeaders.put(AWSConstants.PARTITION_HEADER, directoryArn);

        if (log.isDebugEnabled()) {
            log.debug(String.format("Payload to get incoming TypedLinkSpecifier information : %s ", payload));
        }
        AWSV4Auth aWSV4Auth = new AWSV4Auth.Builder(accessKeyID, secretAccessKey)
                .regionName(region)
                .serviceName(AWSConstants.SERVICE)
                .httpMethodName(AWSConstants.HTTP_POST)
                .canonicalURI(canonicalURI)
                .queryParametes(null)
                .awsHeaders(awsHeaders)
                .payload(payload)
                .build();

        HttpPost httpPost = new HttpPost(AWSConstants.HTTPS + hostHeader + canonicalURI);

        /* Get header calculated for request */
        Map<String, String> header = aWSV4Auth.getHeaders();
        for (Map.Entry<String, String> entrySet : header.entrySet()) {
            httpPost.setHeader(entrySet.getKey(), entrySet.getValue());
        }
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
            httpPost.setHeader(AWSConstants.HOST_HEADER, hostHeader);
            httpPost.setHeader(AWSConstants.PARTITION_HEADER, directoryArn);
            httpPost.setEntity(new StringEntity(payload, AWSConstants.UTF_8));
            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to get incoming TypedLinkSpecifier information.");
            }
            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                handleException(String.format(AWSConstants.STRING_FORMAT, AWSConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY, response));
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), AWSConstants.UTF_8));
            JSONObject responseObject = getParsedObjectByReader(reader);
            System.out.println("Response Object : " + responseObject.toJSONString());
            if (statusCode == HttpStatus.SC_OK) {
                return responseObject;
            } else {
                handleException(String.format("Error occured while getting incoming TypedLinkSpecifier. " +
                        "Response : %s", responseObject.toJSONString()));
            }
        } catch (ParseException e) {
            handleException(AWSConstants.ERROR_WHILE_PARSING_RESPONSE, e);
        } catch (IOException e) {
            handleException(AWSConstants.ERROR_WHILE_READING_RESPONSE, e);
        }
        return null;
    }

    public JSONObject getFacet(String schemaArn, String facetName) throws UserStoreException {

        System.out.println("Inside getFacet--------");
        if (log.isDebugEnabled()) {
            log.debug("Get facet information.");
        }
        String canonicalURI = AWSConstants.AMAZON_CLOUD_DIRECTORY + apiVersion + AWSConstants.GET_FACET;
        TreeMap<String, String> awsHeaders = new TreeMap<>();
        awsHeaders.put(AWSConstants.HOST_HEADER, hostHeader);
        awsHeaders.put(AWSConstants.PARTITION_HEADER, schemaArn);

        String payload = "{\"Name\": \"" + facetName + "\"}";
        if (log.isDebugEnabled()) {
            log.debug(String.format("Payload to get facet information : %s ", payload));
        }
        AWSV4Auth aWSV4Auth = new AWSV4Auth.Builder(accessKeyID, secretAccessKey)
                .regionName(region)
                .serviceName(AWSConstants.SERVICE)
                .httpMethodName(AWSConstants.HTTP_POST)
                .canonicalURI(canonicalURI)
                .queryParametes(null)
                .awsHeaders(awsHeaders)
                .payload(payload)
                .build();

        HttpPost httpPost = new HttpPost(AWSConstants.HTTPS + hostHeader + canonicalURI);

        /* Get header calculated for request */
        Map<String, String> header = aWSV4Auth.getHeaders();
        for (Map.Entry<String, String> entrySet : header.entrySet()) {
            httpPost.setHeader(entrySet.getKey(), entrySet.getValue());
        }
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
            httpPost.setHeader(AWSConstants.HOST_HEADER, hostHeader);
            httpPost.setHeader(AWSConstants.PARTITION_HEADER, schemaArn);
            httpPost.setEntity(new StringEntity(payload, AWSConstants.UTF_8));
            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to get facet information.");
            }
            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                handleException(String.format(AWSConstants.STRING_FORMAT, AWSConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY, response));
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), AWSConstants.UTF_8));
            JSONObject responseObject = getParsedObjectByReader(reader);
            System.out.println("Response Object : " + responseObject.toJSONString());
            if (statusCode == HttpStatus.SC_OK) {
                return responseObject;
            }
        } catch (ParseException e) {
            handleException(AWSConstants.ERROR_WHILE_PARSING_RESPONSE, e);
        } catch (IOException e) {
            handleException(AWSConstants.ERROR_WHILE_READING_RESPONSE, e);
        }
        return null;
    }

    public JSONObject getTypedLinkFacetInformation(String schemaArn, String typedLinkFacetName) throws UserStoreException {

        System.out.println("Inside getTypedLinkFacetInformation--------");
        if (log.isDebugEnabled()) {
            log.debug("Get typed link facet information.");
        }
        String canonicalURI = AWSConstants.AMAZON_CLOUD_DIRECTORY + apiVersion + AWSConstants.GET_TYPED_LINK_FACET;
        TreeMap<String, String> awsHeaders = new TreeMap<>();
        awsHeaders.put(AWSConstants.HOST_HEADER, hostHeader);
        awsHeaders.put(AWSConstants.PARTITION_HEADER, schemaArn);

        String payload = "{\"Name\": \"" + typedLinkFacetName + "\"}";
        if (log.isDebugEnabled()) {
            log.debug(String.format("Payload to get typed link facet information : %s ", payload));
        }
        AWSV4Auth aWSV4Auth = new AWSV4Auth.Builder(accessKeyID, secretAccessKey)
                .regionName(region)
                .serviceName(AWSConstants.SERVICE)
                .httpMethodName(AWSConstants.HTTP_POST)
                .canonicalURI(canonicalURI)
                .queryParametes(null)
                .awsHeaders(awsHeaders)
                .payload(payload)
                .build();

        HttpPost httpPost = new HttpPost(AWSConstants.HTTPS + hostHeader + canonicalURI);

        /* Get header calculated for request */
        Map<String, String> header = aWSV4Auth.getHeaders();
        for (Map.Entry<String, String> entrySet : header.entrySet()) {
            httpPost.setHeader(entrySet.getKey(), entrySet.getValue());
        }
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
            httpPost.setHeader(AWSConstants.HOST_HEADER, hostHeader);
            httpPost.setHeader(AWSConstants.PARTITION_HEADER, schemaArn);
            httpPost.setEntity(new StringEntity(payload, AWSConstants.UTF_8));
            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to get typed link facet information.");
            }
            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                handleException(String.format(AWSConstants.STRING_FORMAT, AWSConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY, response));
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), AWSConstants.UTF_8));
            JSONObject responseObject = getParsedObjectByReader(reader);
            System.out.println("Response Object : " + responseObject.toJSONString());
            if (statusCode == HttpStatus.SC_OK) {
                return responseObject;
            }
        } catch (ParseException e) {
            handleException(AWSConstants.ERROR_WHILE_PARSING_RESPONSE, e);
        } catch (IOException e) {
            handleException(AWSConstants.ERROR_WHILE_READING_RESPONSE, e);
        }
        return null;
    }

    /**
     * Returns a paginated list of child objects that are associated with a given object.
     *
     * @param directoryArn The Amazon Resource Name (ARN) of the directory.
     * @param selector     A path selector selection of an object by the parent/child links.
     * @return List of child objects.
     * @throws UserStoreException If error occurred.
     */
    public JSONObject listObjectChildren(String directoryArn, String selector) throws UserStoreException {

        System.out.println("Inside listObjectChildren----" + directoryArn);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Listing the child objects that are associated with a given object. " +
                    "ObjectReference : %s", selector));
        }
        String canonicalURI = AWSConstants.AMAZON_CLOUD_DIRECTORY + apiVersion + AWSConstants.LIST_OBJECT_CHILDREN;
        TreeMap<String, String> awsHeaders = new TreeMap<>();
        awsHeaders.put(AWSConstants.HOST_HEADER, hostHeader);
        awsHeaders.put(AWSConstants.PARTITION_HEADER, directoryArn);
        awsHeaders.put(AWSConstants.CONSISTENCY_LEVEL_HEADER, AWSConstants.SERIALIZABLE);

        String payload = "{\"ObjectReference\": {\"Selector\": \"" + selector + "\"}}";
        if (log.isDebugEnabled()) {
            log.debug(String.format("Payload to list the child objects of a given object : %s ", payload));
        }
        AWSV4Auth aWSV4Auth = new AWSV4Auth.Builder(accessKeyID, secretAccessKey)
                .regionName(region)
                .serviceName(AWSConstants.SERVICE)
                .httpMethodName(AWSConstants.HTTP_POST)
                .canonicalURI(canonicalURI)
                .queryParametes(null)
                .awsHeaders(awsHeaders)
                .payload(payload)
                .build();

        HttpPost httpPost = new HttpPost(AWSConstants.HTTPS + hostHeader + canonicalURI);

        /* Get header calculated for request */
        Map<String, String> header = aWSV4Auth.getHeaders();
        for (Map.Entry<String, String> entrySet : header.entrySet()) {
            httpPost.setHeader(entrySet.getKey(), entrySet.getValue());
        }
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
            httpPost.setHeader(AWSConstants.HOST_HEADER, hostHeader);
            httpPost.setHeader(AWSConstants.PARTITION_HEADER, directoryArn);
            httpPost.setHeader(AWSConstants.CONSISTENCY_LEVEL_HEADER, AWSConstants.SERIALIZABLE);
            httpPost.setEntity(new StringEntity(payload, AWSConstants.UTF_8));
            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to list the child objects of a given object.");
            }
            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                handleException(String.format(AWSConstants.STRING_FORMAT, AWSConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY,
                        response));
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), AWSConstants.UTF_8));
            JSONObject responseObject = getParsedObjectByReader(reader);
            System.out.println("********" + responseObject);
            if (statusCode == HttpStatus.SC_OK) {
                return responseObject;
            } else {
                handleException(String.format("Error occured while listing the child objects of a given object. " +
                        "ObjectReference : %s, Response : %s", selector, responseObject.toJSONString()));
            }
        } catch (ParseException e) {
            handleException(AWSConstants.ERROR_WHILE_PARSING_RESPONSE, e);
        } catch (IOException e) {
            handleException(AWSConstants.ERROR_WHILE_READING_RESPONSE, e);
        }
        return null;
    }

    /**
     * Deletes an object and its associated attributes.
     *
     * @param directoryArn The Amazon Resource Name (ARN) of the directory.
     * @param selector     A path selector selection of an object by the parent/child links.
     * @return Statuscode for this action.
     * @throws UserStoreException If error occurred.
     */
    public void deleteObject(String directoryArn, String selector) throws UserStoreException {

        System.out.println("Inside deleteObject------------");
        if (log.isDebugEnabled()) {
            log.debug(String.format("Deleting an object with objectReference %s.", selector));
        }
        String canonicalURI = AWSConstants.AMAZON_CLOUD_DIRECTORY + apiVersion + AWSConstants.DELETE_OBJECT;
        TreeMap<String, String> awsHeaders = new TreeMap<>();
        awsHeaders.put(AWSConstants.HOST_HEADER, hostHeader);
        awsHeaders.put(AWSConstants.PARTITION_HEADER, directoryArn);
        String payload = "{\"ObjectReference\": {\"Selector\": \"" + selector + "\"}}";
        if (log.isDebugEnabled()) {
            log.debug(String.format("Payload to delete an object : %s ", payload));
        }
        AWSV4Auth aWSV4Auth = new AWSV4Auth.Builder(accessKeyID, secretAccessKey)
                .regionName(region)
                .serviceName(AWSConstants.SERVICE)
                .httpMethodName(AWSConstants.HTTP_PUT)
                .canonicalURI(canonicalURI)
                .queryParametes(null)
                .awsHeaders(awsHeaders)
                .payload(payload)
                .build();

        HttpPut httpPut = new HttpPut(AWSConstants.HTTPS + hostHeader + canonicalURI);

        /* Get header calculated for request */
        Map<String, String> header = aWSV4Auth.getHeaders();
        for (Map.Entry<String, String> entrySet : header.entrySet()) {
            httpPut.setHeader(entrySet.getKey(), entrySet.getValue());
        }
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
            httpPut.setHeader(AWSConstants.HOST_HEADER, hostHeader);
            httpPut.setHeader(AWSConstants.PARTITION_HEADER, directoryArn);
            httpPut.setEntity(new StringEntity(payload, AWSConstants.UTF_8));
            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to delete an object.");
            }
            HttpResponse response = httpClient.execute(httpPut);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                handleException(String.format(AWSConstants.STRING_FORMAT, AWSConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY, response));
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), AWSConstants.UTF_8));
            JSONObject responseObject = getParsedObjectByReader(reader);
            System.out.println("Status Code is : " + statusCode);
            System.out.println("Response Object : " + responseObject.toJSONString());
            if (statusCode == HttpStatus.SC_OK) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Successfully deleted object. Response : %s", responseObject));
                }
            } else {
                handleException(String.format("Error occured while delete an object. " +
                        "Response : %s", responseObject.toJSONString()));
            }
        } catch (ParseException e) {
            handleException(AWSConstants.ERROR_WHILE_PARSING_RESPONSE, e);
        } catch (IOException e) {
            handleException(AWSConstants.ERROR_WHILE_READING_RESPONSE, e);
        }
    }

    /**
     * Updates a given object's attributes.
     *
     * @param directoryArn The Amazon Resource Name (ARN) of the directory.
     * @param payload      Payload to update object attributes.
     * @return The ObjectIdentifier of the updated object.
     * @throws UserStoreException If error occurred.
     */
    public void updateObjectAttributes(String directoryArn, String payload) throws UserStoreException {

        System.out.println("Inside updateObjectAttributes------------");
        if (log.isDebugEnabled()) {
            log.debug(String.format("Updating a given object's attributes in directory %s.", directoryArn));
        }
        String canonicalURI = AWSConstants.AMAZON_CLOUD_DIRECTORY + apiVersion + AWSConstants.UPDATE_OBJECT;
        TreeMap<String, String> awsHeaders = new TreeMap<>();
        awsHeaders.put(AWSConstants.HOST_HEADER, hostHeader);
        awsHeaders.put(AWSConstants.PARTITION_HEADER, directoryArn);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Payload to update a given object's attributes : %s ", payload));
        }
        AWSV4Auth aWSV4Auth = new AWSV4Auth.Builder(accessKeyID, secretAccessKey)
                .regionName(region)
                .serviceName(AWSConstants.SERVICE)
                .httpMethodName(AWSConstants.HTTP_PUT)
                .canonicalURI(canonicalURI)
                .queryParametes(null)
                .awsHeaders(awsHeaders)
                .payload(payload)
                .build();

        HttpPut httpPut = new HttpPut(AWSConstants.HTTPS + hostHeader + canonicalURI);

        /* Get header calculated for request */
        Map<String, String> header = aWSV4Auth.getHeaders();
        for (Map.Entry<String, String> entrySet : header.entrySet()) {
            httpPut.setHeader(entrySet.getKey(), entrySet.getValue());
        }
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
            httpPut.setHeader(AWSConstants.HOST_HEADER, hostHeader);
            httpPut.setHeader(AWSConstants.PARTITION_HEADER, directoryArn);
            httpPut.setEntity(new StringEntity(payload, AWSConstants.UTF_8));
            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to update a given object's attributes.");
            }
            HttpResponse response = httpClient.execute(httpPut);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                handleException(String.format(AWSConstants.STRING_FORMAT, AWSConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY, response));
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), AWSConstants.UTF_8));
            JSONObject responseObject = getParsedObjectByReader(reader);
            System.out.println("Status Code is : " + statusCode);
            System.out.println("Response Object : " + responseObject.toJSONString());
            if (statusCode == HttpStatus.SC_OK) {
                if (log.isDebugEnabled()) {
                    log.debug("Successfully updated object's attributes");
                }
            } else {
                handleException(String.format("Error occured while update a given object's attributes. " +
                        "Response : %s", responseObject.toJSONString()));
            }
        } catch (ParseException e) {
            handleException(AWSConstants.ERROR_WHILE_PARSING_RESPONSE, e);
        } catch (IOException e) {
            handleException(AWSConstants.ERROR_WHILE_READING_RESPONSE, e);
        }
    }

    /**
     * Detaches a typed link from a specified source and target object.
     *
     * @param directoryArn The Amazon Resource Name (ARN) of the directory.
     * @param payload      Payload to detach type link.
     * @return Statuscode for this action.
     * @throws UserStoreException If error occurred.
     */
    public int detachTypedLink(String directoryArn, String payload) throws UserStoreException {

        System.out.println("Inside detachTypedLink----------");
        if (log.isDebugEnabled()) {
            log.debug(String.format("Detaching a typed link from a specified source and target object in directory %s.",
                    directoryArn));
        }
        String canonicalURI = AWSConstants.AMAZON_CLOUD_DIRECTORY + apiVersion + AWSConstants.DETACH_TYPEDLINK;
        TreeMap<String, String> awsHeaders = new TreeMap<>();
        awsHeaders.put(AWSConstants.HOST_HEADER, hostHeader);
        awsHeaders.put(AWSConstants.PARTITION_HEADER, directoryArn);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Payload to detach a typed link from a specified source and target object : %s ",
                    payload));
        }
        AWSV4Auth aWSV4Auth = new AWSV4Auth.Builder(accessKeyID, secretAccessKey)
                .regionName(region)
                .serviceName(AWSConstants.SERVICE)
                .httpMethodName(AWSConstants.HTTP_PUT)
                .canonicalURI(canonicalURI)
                .queryParametes(null)
                .awsHeaders(awsHeaders)
                .payload(payload)
                .build();

        HttpPut httpPut = new HttpPut(AWSConstants.HTTPS + hostHeader + canonicalURI);

        /* Get header calculated for request */
        Map<String, String> header = aWSV4Auth.getHeaders();
        for (Map.Entry<String, String> entrySet : header.entrySet()) {
            httpPut.setHeader(entrySet.getKey(), entrySet.getValue());
        }
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
            httpPut.setHeader(AWSConstants.HOST_HEADER, hostHeader);
            httpPut.setHeader(AWSConstants.PARTITION_HEADER, directoryArn);
            httpPut.setEntity(new StringEntity(payload, AWSConstants.UTF_8));
            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to detach a typed link from a specified source and target object.");
            }
            HttpResponse response = httpClient.execute(httpPut);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                handleException(String.format(AWSConstants.STRING_FORMAT, AWSConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY,
                        response));
            }
            System.out.println("Status Code is : " + statusCode);
            if (statusCode == HttpStatus.SC_OK) {
                if (log.isDebugEnabled()) {
                    log.debug("Successfully detach a typed link from a specified source and target object");
                }
            } else {
                handleException("Error occured while detach a typed link");
            }
            return statusCode;
        } catch (IOException e) {
            handleException(AWSConstants.ERROR_WHILE_READING_RESPONSE, e);
        }
        return 0;
    }

    /**
     * Detaches a given object from the parent object.
     *
     * @param directoryArn The Amazon Resource Name (ARN) of the directory.
     * @param payload      Payload to detach object.
     * @return The ObjectIdentifier that was detached from the object.
     * @throws UserStoreException If error occurred.
     */
    public JSONObject detachObject(String directoryArn, String payload) throws UserStoreException {

        System.out.println("inside detachObject-----------");
        if (log.isDebugEnabled()) {
            log.debug(String.format("Detaching a given object from the parent object in directory %s.", directoryArn));
        }
        String canonicalURI = AWSConstants.AMAZON_CLOUD_DIRECTORY + apiVersion + AWSConstants.DETACH_OBJECT;
        TreeMap<String, String> awsHeaders = new TreeMap<>();
        awsHeaders.put(AWSConstants.HOST_HEADER, hostHeader);
        awsHeaders.put(AWSConstants.PARTITION_HEADER, directoryArn);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Payload to detach a given object from the parent object : %s ", payload));
        }
        AWSV4Auth aWSV4Auth = new AWSV4Auth.Builder(accessKeyID, secretAccessKey)
                .regionName(region)
                .serviceName(AWSConstants.SERVICE)
                .httpMethodName(AWSConstants.HTTP_PUT)
                .canonicalURI(canonicalURI)
                .queryParametes(null)
                .awsHeaders(awsHeaders)
                .payload(payload)
                .build();

        HttpPut httpPut = new HttpPut(AWSConstants.HTTPS + hostHeader + canonicalURI);

        /* Get header calculated for request */
        Map<String, String> header = aWSV4Auth.getHeaders();
        for (Map.Entry<String, String> entrySet : header.entrySet()) {
            httpPut.setHeader(entrySet.getKey(), entrySet.getValue());
        }
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
            httpPut.setHeader(AWSConstants.HOST_HEADER, hostHeader);
            httpPut.setHeader(AWSConstants.PARTITION_HEADER, directoryArn);
            httpPut.setEntity(new StringEntity(payload, AWSConstants.UTF_8));
            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to detach a given object from the parent object.");
            }
            HttpResponse response = httpClient.execute(httpPut);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                handleException(String.format(AWSConstants.STRING_FORMAT, AWSConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY, response));
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), AWSConstants.UTF_8));
            JSONObject responseObject = getParsedObjectByReader(reader);
            System.out.println("Status Code is : " + statusCode);
            System.out.println("Response Object : " + responseObject.toJSONString());
            if (statusCode == HttpStatus.SC_OK) {
                return responseObject;
            } else {
                handleException(String.format("Error occured while detach a given object from the parent object. " +
                        "Response : %s", responseObject.toJSONString()));
            }
        } catch (ParseException e) {
            handleException(AWSConstants.ERROR_WHILE_PARSING_RESPONSE, e);
        } catch (IOException e) {
            handleException(AWSConstants.ERROR_WHILE_READING_RESPONSE, e);
        }
        return null;
    }

    public JSONObject updateFacet(String schemaArn, String payload) throws UserStoreException {

        System.out.println("inside updateFacet-----------");
        if (log.isDebugEnabled()) {
            log.debug(String.format("Updating facet with schema arn: %s.", schemaArn));
        }
        String canonicalURI = AWSConstants.AMAZON_CLOUD_DIRECTORY + apiVersion + AWSConstants.UPDATE_FACET;
        TreeMap<String, String> awsHeaders = new TreeMap<>();
        awsHeaders.put(AWSConstants.HOST_HEADER, hostHeader);
        awsHeaders.put(AWSConstants.PARTITION_HEADER, schemaArn);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Payload to update a facet : %s ", payload));
        }
        AWSV4Auth aWSV4Auth = new AWSV4Auth.Builder(accessKeyID, secretAccessKey)
                .regionName(region)
                .serviceName(AWSConstants.SERVICE)
                .httpMethodName(AWSConstants.HTTP_PUT)
                .canonicalURI(canonicalURI)
                .queryParametes(null)
                .awsHeaders(awsHeaders)
                .payload(payload)
                .build();

        HttpPut httpPut = new HttpPut(AWSConstants.HTTPS + hostHeader + canonicalURI);

        /* Get header calculated for request */
        Map<String, String> header = aWSV4Auth.getHeaders();
        for (Map.Entry<String, String> entrySet : header.entrySet()) {
            httpPut.setHeader(entrySet.getKey(), entrySet.getValue());
        }
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
            httpPut.setHeader(AWSConstants.HOST_HEADER, hostHeader);
            httpPut.setHeader(AWSConstants.PARTITION_HEADER, schemaArn);
            httpPut.setEntity(new StringEntity(payload, AWSConstants.UTF_8));
            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to update a facet.");
            }
            HttpResponse response = httpClient.execute(httpPut);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                handleException(String.format(AWSConstants.STRING_FORMAT, AWSConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY, response));
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), AWSConstants.UTF_8));
            JSONObject responseObject = getParsedObjectByReader(reader);
            System.out.println("Status Code is : " + statusCode);
            System.out.println("Response Object : " + responseObject.toJSONString());
            if (statusCode == HttpStatus.SC_OK) {
                return responseObject;
            } else {
                handleException(String.format("Error occured while updating a facet. " +
                        "Response : %s", responseObject.toJSONString()));
            }
        } catch (ParseException e) {
            handleException(AWSConstants.ERROR_WHILE_PARSING_RESPONSE, e);
        } catch (IOException e) {
            handleException(AWSConstants.ERROR_WHILE_READING_RESPONSE, e);
        }
        return null;
    }

    /**
     * Retrieves metadata about an object.
     *
     * @param directoryArn The Amazon Resource Name (ARN) of the directory.
     * @param selector     A path selector selection of an object by the parent/child links.
     * @return Object infomation.
     * @throws UserStoreException If error occurred.
     */
    public JSONObject getObjectInformation(String directoryArn, String selector) throws UserStoreException {

        System.out.println("Inside getObjectInformation");
        if (log.isDebugEnabled()) {
            log.debug(String.format("Retrieving meta data about an object with objectReference %s.", selector));
        }
        String canonicalURI = AWSConstants.AMAZON_CLOUD_DIRECTORY + apiVersion + AWSConstants.GET_OBJECT_INFORMATION;
        TreeMap<String, String> awsHeaders = new TreeMap<>();
        awsHeaders.put(AWSConstants.HOST_HEADER, hostHeader);
        awsHeaders.put(AWSConstants.PARTITION_HEADER, directoryArn);
        awsHeaders.put(AWSConstants.CONSISTENCY_LEVEL_HEADER, AWSConstants.SERIALIZABLE);

        String payload = "{\"ObjectReference\": {\"Selector\": \"" + selector + "\"}}";
        if (log.isDebugEnabled()) {
            log.debug(String.format("Payload to Retrieve metadata about an object : %s ", payload));
        }
        AWSV4Auth aWSV4Auth = new AWSV4Auth.Builder(accessKeyID, secretAccessKey)
                .regionName(region)
                .serviceName(AWSConstants.SERVICE)
                .httpMethodName(AWSConstants.HTTP_POST)
                .canonicalURI(canonicalURI)
                .queryParametes(null)
                .awsHeaders(awsHeaders)
                .payload(payload)
                .build();

        HttpPost httpPost = new HttpPost(AWSConstants.HTTPS + hostHeader + canonicalURI);

        /* Get header calculated for request */
        Map<String, String> header = aWSV4Auth.getHeaders();
        for (Map.Entry<String, String> entrySet : header.entrySet()) {
            httpPost.setHeader(entrySet.getKey(), entrySet.getValue());
        }
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
            httpPost.setHeader(AWSConstants.HOST_HEADER, hostHeader);
            httpPost.setHeader(AWSConstants.PARTITION_HEADER, directoryArn);
            httpPost.setHeader(AWSConstants.CONSISTENCY_LEVEL_HEADER, AWSConstants.SERIALIZABLE);
            httpPost.setEntity(new StringEntity(payload, AWSConstants.UTF_8));
            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to retrieve metadata about an object.");
            }
            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                handleException(String.format(AWSConstants.STRING_FORMAT, AWSConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY, response));
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), AWSConstants.UTF_8));
            JSONObject responseObject = getParsedObjectByReader(reader);
            System.out.println("*********#####################*************" + responseObject);
            if (statusCode == HttpStatus.SC_OK) {
                return responseObject;
            } else {
                log.error(String.format("Error occured while retrieve metadata of an object with " +
                        "objectReference %s. Response : %s", selector, responseObject.toJSONString()));
            }
        } catch (ParseException e) {
            handleException(AWSConstants.ERROR_WHILE_PARSING_RESPONSE, e);
        } catch (IOException e) {
            handleException(AWSConstants.ERROR_WHILE_READING_RESPONSE, e);
        }
        return null;
    }

    /**
     * Lists all attributes that are associated with an object.
     *
     * @param directoryArn The Amazon Resource Name (ARN) of the directory.
     * @param payload      Payload to list object attributes.
     * @return Object attributes.
     * @throws UserStoreException If error occurred.
     */
    public JSONObject listObjectAttributes(String directoryArn, String payload) throws UserStoreException {

        System.out.println("Inside listObjectAttributes----");
        if (log.isDebugEnabled()) {
            log.debug("Listing all attributes of an object.");
        }
        String canonicalURI = AWSConstants.AMAZON_CLOUD_DIRECTORY + apiVersion + AWSConstants.LIST_OBJECT_ATTRIBUTES;
        TreeMap<String, String> awsHeaders = new TreeMap<>();
        awsHeaders.put(AWSConstants.HOST_HEADER, hostHeader);
        awsHeaders.put(AWSConstants.PARTITION_HEADER, directoryArn);
        awsHeaders.put(AWSConstants.CONSISTENCY_LEVEL_HEADER, AWSConstants.SERIALIZABLE);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Payload to list all attributes of an object : %s ", payload));
        }
        AWSV4Auth aWSV4Auth = new AWSV4Auth.Builder(accessKeyID, secretAccessKey)
                .regionName(region)
                .serviceName(AWSConstants.SERVICE)
                .httpMethodName(AWSConstants.HTTP_POST)
                .canonicalURI(canonicalURI)
                .queryParametes(null)
                .awsHeaders(awsHeaders)
                .payload(payload)
                .build();

        HttpPost httpPost = new HttpPost(AWSConstants.HTTPS + hostHeader + canonicalURI);

        /* Get header calculated for request */
        Map<String, String> header = aWSV4Auth.getHeaders();
        for (Map.Entry<String, String> entrySet : header.entrySet()) {
            httpPost.setHeader(entrySet.getKey(), entrySet.getValue());
        }
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
            httpPost.setHeader(AWSConstants.HOST_HEADER, hostHeader);
            httpPost.setHeader(AWSConstants.PARTITION_HEADER, directoryArn);
            httpPost.setHeader(AWSConstants.CONSISTENCY_LEVEL_HEADER, AWSConstants.SERIALIZABLE);
            httpPost.setEntity(new StringEntity(payload, AWSConstants.UTF_8));
            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to list all attributes of an object.");
            }
            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                handleException(String.format(AWSConstants.STRING_FORMAT, AWSConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY, response));
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), AWSConstants.UTF_8));
            JSONObject responseObject = getParsedObjectByReader(reader);
            System.out.println(responseObject);
            if (statusCode == HttpStatus.SC_OK) {
                return responseObject;
            } else {
                handleException(String.format("Error occured while list all attributes of an object. " +
                        "Response : %s", responseObject.toJSONString()));
            }
        } catch (ParseException e) {
            handleException(AWSConstants.ERROR_WHILE_PARSING_RESPONSE, e);
        } catch (IOException e) {
            handleException(AWSConstants.ERROR_WHILE_READING_RESPONSE, e);
        }
        return null;
    }

    public JSONObject listFacetAttributes(String schemaArn, String payload) throws UserStoreException {

        System.out.println("Inside listFacetAttributes----");
        if (log.isDebugEnabled()) {
            log.debug("Listing all attributes of an facet.");
        }
        String canonicalURI = AWSConstants.AMAZON_CLOUD_DIRECTORY + apiVersion + AWSConstants.LIST_FACET_ATTRIBUTES;
        TreeMap<String, String> awsHeaders = new TreeMap<>();
        awsHeaders.put(AWSConstants.HOST_HEADER, hostHeader);
        awsHeaders.put(AWSConstants.PARTITION_HEADER, schemaArn);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Payload to list all attributes of an facet : %s ", payload));
        }
        AWSV4Auth aWSV4Auth = new AWSV4Auth.Builder(accessKeyID, secretAccessKey)
                .regionName(region)
                .serviceName(AWSConstants.SERVICE)
                .httpMethodName(AWSConstants.HTTP_POST)
                .canonicalURI(canonicalURI)
                .queryParametes(null)
                .awsHeaders(awsHeaders)
                .payload(payload)
                .build();

        HttpPost httpPost = new HttpPost(AWSConstants.HTTPS + hostHeader + canonicalURI);

        /* Get header calculated for request */
        Map<String, String> header = aWSV4Auth.getHeaders();
        for (Map.Entry<String, String> entrySet : header.entrySet()) {
            httpPost.setHeader(entrySet.getKey(), entrySet.getValue());
        }
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
            httpPost.setHeader(AWSConstants.HOST_HEADER, hostHeader);
            httpPost.setHeader(AWSConstants.PARTITION_HEADER, schemaArn);
            httpPost.setEntity(new StringEntity(payload, AWSConstants.UTF_8));
            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to list all attributes of an facet.");
            }
            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                handleException(String.format(AWSConstants.STRING_FORMAT, AWSConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY, response));
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), AWSConstants.UTF_8));
            JSONObject responseObject = getParsedObjectByReader(reader);
            System.out.println(responseObject);
            if (statusCode == HttpStatus.SC_OK) {
                return responseObject;
            } else {
                handleException(String.format("Error occured while list all attributes of an facet. " +
                        "Response : %s", responseObject.toJSONString()));
            }
        } catch (ParseException e) {
            handleException(AWSConstants.ERROR_WHILE_PARSING_RESPONSE, e);
        } catch (IOException e) {
            handleException(AWSConstants.ERROR_WHILE_READING_RESPONSE, e);
        }
        return null;
    }

    /**
     * Creates a new schema in a development state.
     *
     * @return Directory schema name.
     * @throws UserStoreException If error occurred.
     */
    public String createDirectorySchema() throws UserStoreException {

        System.out.println("inside createDirectorySchema");
        if (log.isDebugEnabled()) {
            log.debug("Creating a new schema.");
        }
        String canonicalURI = AWSConstants.AMAZON_CLOUD_DIRECTORY + apiVersion + AWSConstants.CREATE_SCHEMA;
        TreeMap<String, String> awsHeaders = new TreeMap<>();
        awsHeaders.put(AWSConstants.HOST_HEADER, hostHeader);

        String payload = "{\"Name\":\"" + AWSConstants.SCHEMA_NAME + "\"}";
        if (log.isDebugEnabled()) {
            log.debug(String.format("Payload to create a new schema : %s ", payload));
        }
        AWSV4Auth aWSV4Auth = new AWSV4Auth.Builder(accessKeyID, secretAccessKey)
                .regionName(region)
                .serviceName(AWSConstants.SERVICE)
                .httpMethodName(AWSConstants.HTTP_PUT)
                .canonicalURI(canonicalURI)
                .queryParametes(null)
                .awsHeaders(awsHeaders)
                .payload(payload)
                .build();

        HttpPut httpPut = new HttpPut(AWSConstants.HTTPS + hostHeader + canonicalURI);

        /* Get header calculated for request */
        Map<String, String> header = aWSV4Auth.getHeaders();
        for (Map.Entry<String, String> entrySet : header.entrySet()) {
            httpPut.setHeader(entrySet.getKey(), entrySet.getValue());
        }
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
            httpPut.setHeader(AWSConstants.HOST_HEADER, hostHeader);
            httpPut.setEntity(new StringEntity(payload, AWSConstants.UTF_8));
            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to create a new schema.");
            }
            HttpResponse response = httpClient.execute(httpPut);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                handleException(String.format(AWSConstants.STRING_FORMAT, AWSConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY, response));
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), AWSConstants.UTF_8));
            JSONObject responseObject = getParsedObjectByReader(reader);
            System.out.println("responseObject " + responseObject.toJSONString());
            if (statusCode == HttpStatus.SC_OK) {
                return (String) responseObject.get("SchemaArn");
            } else {
                handleException(String.format("Error occured while create a new schema. " +
                        "Response : %s", responseObject.toJSONString()));
            }
        } catch (ParseException e) {
            handleException(AWSConstants.ERROR_WHILE_PARSING_RESPONSE, e);
        } catch (IOException e) {
            handleException(AWSConstants.ERROR_WHILE_READING_RESPONSE, e);
        }
        return null;
    }

    /**
     * Attaches a typed link to a specified source and target object.
     *
     * @param payload      Payload to attach typelink.
     * @param directoryArn The Amazon Resource Name (ARN) of the directory.
     * @return Returns a typed link specifier as output.
     * @throws UserStoreException If error occurred.
     */
    public void attachTypedLink(String directoryArn, String payload) throws UserStoreException {

        System.out.println("Inside attachTypedLink------------");
        if (log.isDebugEnabled()) {
            log.debug("Attaching a typed link to a specified source and target object.");
        }
        String canonicalURI = AWSConstants.AMAZON_CLOUD_DIRECTORY + apiVersion + AWSConstants.ATTACH_TYPEDLINK;
        TreeMap<String, String> awsHeaders = new TreeMap<>();
        awsHeaders.put(AWSConstants.HOST_HEADER, hostHeader);
        awsHeaders.put(AWSConstants.PARTITION_HEADER, directoryArn);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Payload to attach a typed link to a specified source and target object : %s ",
                    payload));
        }
        AWSV4Auth aWSV4Auth = new AWSV4Auth.Builder(accessKeyID, secretAccessKey)
                .regionName(region)
                .serviceName(AWSConstants.SERVICE)
                .httpMethodName(AWSConstants.HTTP_PUT)
                .canonicalURI(canonicalURI)
                .queryParametes(null)
                .awsHeaders(awsHeaders)
                .payload(payload)
                .build();

        HttpPut httpPut = new HttpPut(AWSConstants.HTTPS + hostHeader + canonicalURI);

        /* Get header calculated for request */
        Map<String, String> header = aWSV4Auth.getHeaders();
        for (Map.Entry<String, String> entrySet : header.entrySet()) {
            httpPut.setHeader(entrySet.getKey(), entrySet.getValue());
        }
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
            httpPut.setHeader(AWSConstants.HOST_HEADER, hostHeader);
            httpPut.setHeader(AWSConstants.PARTITION_HEADER, directoryArn);
            httpPut.setEntity(new StringEntity(payload, AWSConstants.UTF_8));
            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to attach a typed link to a specified source and target object.");
            }
            HttpResponse response = httpClient.execute(httpPut);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                handleException(String.format(AWSConstants.STRING_FORMAT, AWSConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY,
                        response));
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), AWSConstants.UTF_8));
            JSONObject responseObject = getParsedObjectByReader(reader);
            System.out.println("Status Code is : " + statusCode);
            System.out.println("Response Object : " + responseObject.toJSONString());
            if (statusCode == HttpStatus.SC_OK) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Successfully attached a typed link. Response : %s",
                            responseObject.toJSONString()));
                }
            } else {
                handleException(String.format("Error occured while attach a typed link to a specified source and " +
                        "target object. Response : %s", responseObject.toJSONString()));
            }
        } catch (ParseException e) {
            handleException(AWSConstants.ERROR_WHILE_PARSING_RESPONSE, e);
        } catch (IOException e) {
            handleException(AWSConstants.ERROR_WHILE_READING_RESPONSE, e);
        }
    }

    /**
     * Creates a TypedLinkFacet.
     *
     * @param payload   Payload to create typed link facet.
     * @param schemaArn The schema ARN in which the new Facet will be created.
     * @return TypedLink facet.
     * @throws UserStoreException If error occurred.
     */
    public void createTypedLinkFacet(String schemaArn, String payload) throws UserStoreException {

        System.out.println("inside createTypedLinkFacet-----------");
        if (log.isDebugEnabled()) {
            log.debug(String.format("Creating a TypedLinkFacet in schema %s.", schemaArn));
        }
        String canonicalURI = AWSConstants.AMAZON_CLOUD_DIRECTORY + apiVersion + AWSConstants.CREATE_TYPEDLINK;
        TreeMap<String, String> awsHeaders = new TreeMap<>();
        awsHeaders.put(AWSConstants.HOST_HEADER, hostHeader);
        awsHeaders.put(AWSConstants.PARTITION_HEADER, schemaArn);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Payload to create a TypedLinkFacet : %s ", payload));
        }
        AWSV4Auth aWSV4Auth = new AWSV4Auth.Builder(accessKeyID, secretAccessKey)
                .regionName(region)
                .serviceName(AWSConstants.SERVICE)
                .httpMethodName(AWSConstants.HTTP_PUT)
                .canonicalURI(canonicalURI)
                .queryParametes(null)
                .awsHeaders(awsHeaders)
                .payload(payload)
                .build();

        HttpPut httpPut = new HttpPut(AWSConstants.HTTPS + hostHeader + canonicalURI);

        /* Get header calculated for request */
        Map<String, String> header = aWSV4Auth.getHeaders();
        for (Map.Entry<String, String> entrySet : header.entrySet()) {
            httpPut.setHeader(entrySet.getKey(), entrySet.getValue());
        }
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
            httpPut.setHeader(AWSConstants.HOST_HEADER, hostHeader);
            httpPut.setHeader(AWSConstants.PARTITION_HEADER, schemaArn);
            httpPut.setEntity(new StringEntity(payload, AWSConstants.UTF_8));
            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to create a TypedLinkFacet.");
            }
            HttpResponse response = httpClient.execute(httpPut);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                handleException(String.format(AWSConstants.STRING_FORMAT, AWSConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY,
                        response));
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), AWSConstants.UTF_8));
            JSONObject responseObject = getParsedObjectByReader(reader);
            System.out.println("Status Code is : " + statusCode);
            System.out.println("Response Object : " + responseObject.toJSONString());
            if (statusCode == HttpStatus.SC_OK) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("TypedLinkFacet is created successfully. Response : %s ",
                            responseObject.toJSONString()));
                }
            } else {
                handleException(String.format("Error occured while create a TypedLinkFacet. " +
                        "Response : %s", responseObject.toJSONString()));
            }
        } catch (ParseException e) {
            handleException(AWSConstants.ERROR_WHILE_PARSING_RESPONSE, e);
        } catch (IOException e) {
            handleException(AWSConstants.ERROR_WHILE_READING_RESPONSE, e);
        }
    }

    /**
     * Creates an object in a Directory.
     *
     * @param directoryArn The Amazon Resource Name (ARN) of the directory.
     * @param payload      Payload to create object.
     * @return Object identifier.
     * @throws UserStoreException If error occurred.
     */
    public void createObject(String directoryArn, String payload) throws UserStoreException {

        System.out.println("Inside createObject-------");
        if (log.isDebugEnabled()) {
            log.debug(String.format("Creating an object in a Directory with directory Arn %s.", directoryArn));
        }
        String canonicalURI = AWSConstants.AMAZON_CLOUD_DIRECTORY + apiVersion + AWSConstants.CREATE_OBJECT;
        TreeMap<String, String> awsHeaders = new TreeMap<>();
        awsHeaders.put(AWSConstants.HOST_HEADER, hostHeader);
        awsHeaders.put(AWSConstants.PARTITION_HEADER, directoryArn);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Payload to create an object in a directory : %s ", payload));
        }
        AWSV4Auth aWSV4Auth = new AWSV4Auth.Builder(accessKeyID, secretAccessKey)
                .regionName(region)
                .serviceName(AWSConstants.SERVICE)
                .httpMethodName(AWSConstants.HTTP_PUT)
                .canonicalURI(canonicalURI)
                .queryParametes(null)
                .awsHeaders(awsHeaders)
                .payload(payload)
                .build();

        HttpPut httpPut = new HttpPut(AWSConstants.HTTPS + hostHeader + canonicalURI);

        /* Get header calculated for request */
        Map<String, String> header = aWSV4Auth.getHeaders();
        for (Map.Entry<String, String> entrySet : header.entrySet()) {
            httpPut.setHeader(entrySet.getKey(), entrySet.getValue());
        }
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
            httpPut.setHeader(AWSConstants.HOST_HEADER, hostHeader);
            httpPut.setHeader(AWSConstants.PARTITION_HEADER, directoryArn);
            httpPut.setEntity(new StringEntity(payload, AWSConstants.UTF_8));
            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to create an object in a directory.");
            }
            HttpResponse response = httpClient.execute(httpPut);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                handleException(String.format(AWSConstants.STRING_FORMAT, AWSConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY,
                        response));
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), AWSConstants.UTF_8));
            JSONObject responseObject = getParsedObjectByReader(reader);
            System.out.println("After creating user object---------------------" + statusCode);
            System.out.println(responseObject);
            if (statusCode == HttpStatus.SC_OK) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Object is created successfull with ObjectIdentifier %s ",
                            responseObject.get("ObjectIdentifier")));
                }
            } else {
                handleException(String.format("Error occured while create an object in a directory %s. " +
                        "Response : %s", directoryArn, responseObject.toJSONString()));
            }
        } catch (ParseException e) {
            handleException(AWSConstants.ERROR_WHILE_PARSING_RESPONSE, e);
        } catch (IOException e) {
            handleException(AWSConstants.ERROR_WHILE_READING_RESPONSE, e);
        }
    }

    /**
     * Creates a new Facet in a schema.
     *
     * @param schemaArn    The schema ARN in which the new Facet will be created.
     * @param facetPayload Payload to create schema facet.
     * @throws UserStoreException If error occurred.
     */
    public void createSchemaFacet(String schemaArn, String facetPayload) throws UserStoreException {

        System.out.println("Inside createSchemaFacet-----------");
        if (log.isDebugEnabled()) {
            log.debug(String.format("Creating a new Facet in a schema %s .", schemaArn));
        }
        String canonicalURI = AWSConstants.AMAZON_CLOUD_DIRECTORY + apiVersion + AWSConstants.CREATE_FACET;
        TreeMap<String, String> awsHeaders = new TreeMap<>();
        awsHeaders.put(AWSConstants.HOST_HEADER, hostHeader);
        awsHeaders.put(AWSConstants.PARTITION_HEADER, schemaArn);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Payload to create a new facet in a schema : %s ", facetPayload));
        }
        AWSV4Auth aWSV4Auth = new AWSV4Auth.Builder(accessKeyID, secretAccessKey)
                .regionName(region)
                .serviceName(AWSConstants.SERVICE)
                .httpMethodName(AWSConstants.HTTP_PUT)
                .canonicalURI(canonicalURI)
                .queryParametes(null)
                .awsHeaders(awsHeaders)
                .payload(facetPayload)
                .build();

        HttpPut httpPut = new HttpPut(AWSConstants.HTTPS + hostHeader + canonicalURI);

        /* Get header calculated for request */
        Map<String, String> header = aWSV4Auth.getHeaders();
        for (Map.Entry<String, String> entrySet : header.entrySet()) {
            httpPut.setHeader(entrySet.getKey(), entrySet.getValue());
        }
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
            httpPut.setHeader(AWSConstants.HOST_HEADER, hostHeader);
            httpPut.setHeader(AWSConstants.PARTITION_HEADER, schemaArn);
            httpPut.setEntity(new StringEntity(facetPayload, AWSConstants.UTF_8));
            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to create a new facet in a schema.");
            }
            HttpResponse response = httpClient.execute(httpPut);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                handleException(String.format(AWSConstants.STRING_FORMAT, AWSConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY, response));
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), AWSConstants.UTF_8));
            JSONObject responseObject = getParsedObjectByReader(reader);
            System.out.println("responseObject" + responseObject.toJSONString());
            if (statusCode == HttpStatus.SC_OK) {
                if (log.isDebugEnabled()) {
                    log.debug("Schema facet is created successfully. Response Object : " + responseObject.toJSONString());
                }
            } else {
                handleException(String.format("Error occured while create a new facet in a schema %s. " +
                        "Response : %s", schemaArn, responseObject.toJSONString()));
            }
        } catch (ParseException e) {
            handleException(AWSConstants.ERROR_WHILE_PARSING_RESPONSE, e);
        } catch (IOException e) {
            handleException(AWSConstants.ERROR_WHILE_READING_RESPONSE, e);
        }
    }

    /**
     * Publishes a development schema with a major version and a recommended minor version.
     *
     * @param developmentSchemaArn The schema ARN which need to be published.
     * @return Published schema ARN.
     * @throws UserStoreException If error occurred.
     */
    public String publishSchema(String developmentSchemaArn) throws UserStoreException {

        System.out.println("Inside publishSchema-----------");
        if (log.isDebugEnabled()) {
            log.debug(String.format("Publishing a development schema %s .", developmentSchemaArn));
        }
        String canonicalURI = AWSConstants.AMAZON_CLOUD_DIRECTORY + apiVersion + AWSConstants.PUBLISH_SCHEMA;
        TreeMap<String, String> awsHeaders = new TreeMap<>();
        awsHeaders.put(AWSConstants.HOST_HEADER, hostHeader);
        awsHeaders.put(AWSConstants.PARTITION_HEADER, developmentSchemaArn);
        String payload = "{\"Version\":\"1.0\"}";
        if (log.isDebugEnabled()) {
            log.debug(String.format("Payload to publish a development schema : %s ", payload));
        }
        AWSV4Auth aWSV4Auth = new AWSV4Auth.Builder(accessKeyID, secretAccessKey)
                .regionName(region)
                .serviceName(AWSConstants.SERVICE)
                .httpMethodName(AWSConstants.HTTP_PUT)
                .canonicalURI(canonicalURI)
                .queryParametes(null)
                .awsHeaders(awsHeaders)
                .payload(payload)
                .build();

        HttpPut httpPut = new HttpPut(AWSConstants.HTTPS + hostHeader + canonicalURI);

        /* Get header calculated for request */
        Map<String, String> header = aWSV4Auth.getHeaders();
        for (Map.Entry<String, String> entrySet : header.entrySet()) {
            httpPut.setHeader(entrySet.getKey(), entrySet.getValue());
        }
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
            httpPut.setHeader(AWSConstants.HOST_HEADER, hostHeader);
            httpPut.setHeader(AWSConstants.PARTITION_HEADER, developmentSchemaArn);
            httpPut.setEntity(new StringEntity(payload, AWSConstants.UTF_8));
            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to publish a development schema.");
            }
            HttpResponse response = httpClient.execute(httpPut);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                handleException(String.format(AWSConstants.STRING_FORMAT, AWSConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY,
                        response));
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), AWSConstants.UTF_8));
            JSONObject responseObject = getParsedObjectByReader(reader);
            System.out.println("responseObject" + responseObject.toJSONString());
            if (statusCode == HttpStatus.SC_OK) {
                return (String) responseObject.get("PublishedSchemaArn");
            } else {
                handleException(String.format("Error occured while publish a development schema %s . " +
                        "Response : %s", developmentSchemaArn, responseObject.toJSONString()));
            }
        } catch (ParseException e) {
            handleException(AWSConstants.ERROR_WHILE_PARSING_RESPONSE, e);
        } catch (IOException e) {
            handleException(AWSConstants.ERROR_WHILE_READING_RESPONSE, e);
        }
        return null;
    }

    /**
     * Creates a Directory by copying the published schema into the directory.
     *
     * @param schemaArn The Amazon Resource Name (ARN) of the published schema that will be copied into the
     *                  data Directory.
     * @return Directory information.
     * @throws UserStoreException If error occurred.
     */
    public JSONObject createDirectory(String schemaArn) throws UserStoreException {

        System.out.println("Inside createDirectory-------");
        if (log.isDebugEnabled()) {
            log.debug(String.format("Creating new directory with schema %s.", schemaArn));
        }
        String canonicalURI = AWSConstants.AMAZON_CLOUD_DIRECTORY +
                apiVersion + AWSConstants.CREATE_DIRECTORY;
        TreeMap<String, String> awsHeaders = new TreeMap<>();
        awsHeaders.put(AWSConstants.HOST_HEADER, hostHeader);
        awsHeaders.put(AWSConstants.PARTITION_HEADER, schemaArn);
        String payload = "{\"Name\":\"" + AWSConstants.DIRECTORY_NAME + "\"}";
        if (log.isDebugEnabled()) {
            log.debug(String.format("Payload to create new directory : %s ", payload));
        }
        AWSV4Auth aWSV4Auth = new AWSV4Auth.Builder(accessKeyID, secretAccessKey)
                .regionName(region)
                .serviceName(AWSConstants.SERVICE)
                .httpMethodName(AWSConstants.HTTP_PUT)
                .canonicalURI(canonicalURI)
                .queryParametes(null)
                .awsHeaders(awsHeaders)
                .payload(payload)
                .build();

        HttpPut httpPut = new HttpPut(AWSConstants.HTTPS + hostHeader + canonicalURI);

        /* Get header calculated for request */
        Map<String, String> header = aWSV4Auth.getHeaders();
        for (Map.Entry<String, String> entrySet : header.entrySet()) {
            httpPut.setHeader(entrySet.getKey(), entrySet.getValue());
        }
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
            httpPut.setHeader(AWSConstants.HOST_HEADER, hostHeader);
            httpPut.setHeader(AWSConstants.PARTITION_HEADER, schemaArn);
            httpPut.setEntity(new StringEntity(payload, AWSConstants.UTF_8));
            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to create new directory.");
            }
            HttpResponse response = httpClient.execute(httpPut);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                handleException(String.format(AWSConstants.STRING_FORMAT, AWSConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY, response));
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), AWSConstants.UTF_8));
            JSONObject responseObject = getParsedObjectByReader(reader);
            System.out.println("responseObject " + responseObject);
            if (statusCode == HttpStatus.SC_OK) {
                return responseObject;
            } else {
                handleException(String.format("Error occured while create new directory for schema %s . " +
                        "Response : %s", schemaArn, responseObject.toJSONString()));
            }
        } catch (ParseException e) {
            handleException(AWSConstants.ERROR_WHILE_PARSING_RESPONSE, e);
        } catch (IOException e) {
            handleException(AWSConstants.ERROR_WHILE_READING_RESPONSE, e);
        }
        return null;
    }

    /**
     * Can be used to parse {@code BufferedReader} object that are taken from response stream, to a {@code JSONObject}.
     *
     * @param reader {@code BufferedReader} object from response.
     * @return JSON payload as a name value map.
     * @throws ParseException Error while parsing response json.
     * @throws IOException Error while reading response body
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
     * Common method to throw exceptions.
     *
     * @param msg this parameter contain error message that we need to throw.
     * @param e   Exception object.
     * @throws UserStoreException If error occurred.
     */
    private static void handleException(String msg, Exception e) throws UserStoreException {

        log.error(msg, e);
        throw new UserStoreException(msg, e);
    }

    /**
     * Common method to throw exceptions. This will only expect one parameter.
     *
     * @param msg error message as a string.
     * @throws UserStoreException If error occurred.
     */
    private static void handleException(String msg) throws UserStoreException {

        log.error(msg);
        throw new UserStoreException(msg);
    }
}
