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
package org.wso2.carbon.user.aws;

/**
 * TODO: Class level comment.
 */
public class AWSConstants {
    public static final String ACCESS_KEY_ID = "AccessKeyID";
    public static final String SECRET_ACCESS_KEY = "SecretAccessKey";
    public static final String REGION = "Region";
    public static final String API_VERSION = "APIVersion";
    public static final String PATH_TO_USERS = "PathToUsers";
    public static final String PATH_TO_ROLES = "PathToRoles";
    public static final String MEMBERSHIP_TYPE_OF_ROLES = "MembershipTypeOfRoles";
    public static final String ATTRIBUTE_NAMES_OF_USER_ENTITY = "attributesNameOfUser";
    public static final String FACET_NAME_OF_USER = "FacetNameOfUser";
    public static final String FACET_NAME_OF_ROLE = "FacetNameOfRole";
    public static final String USER_NAME_ATTRIBUTE = "UserNameAttribute";
    public static final String PASSWORD_ATTRIBUTE = "PasswordAttribute";
    public static final String ROLE_NAME_ATTRIBUTE = "RoleNameAttribute";
    public static final String SERVICE = "clouddirectory";
    public static final String AMAZON_AWS_COM = ".amazonaws.com";
    public static final String HTTP_POST = "POST";
    public static final String HOST_HEADER = "host";
    public static final String DATE_HEADER = "x-amz-date";
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String PARTITION_HEADER = "x-amz-data-partition";
    public static final String CONSISTENCY_LEVEL_HEADER = "x-amz-consistency-level";
    public static final String SERIALIZABLE = "SERIALIZABLE";
    public static final String HTTP_PUT = "PUT";
    public static final String DIRECTORY_NAME = "TestsampleDir";
    public static final String SCHEMA_NAME = "sampleTestSchema";
    public static final String HTTPS = "https://";
    public static final String GROUP = "GROUP";
    public static final String ROLE_FACET = "role_facet";
    public static final String USER_FACET = "user_facet";
    public static final String USER_ATTRIBUTE_FACET = "user_attribute_facet";
    public static final String JSON = ".json";
    public static final String FACETS = "/facets/";
    public static final String AMAZON_CLOUD_DIRECTORY = "/amazonclouddirectory/";
    public static final String CREATE_DIRECTORY = "/directory/create";
    public static final String PUBLISH_SCHEMA = "/schema/publish";
    public static final String CREATE_FACET = "/facet/create";
    public static final String CREATE_OBJECT = "/object";
    public static final String CREATE_TYPEDLINK = "/typedlink/facet/create";
    public static final String CREATE_SCHEMA = "/schema/create";
    public static final String ATTACH_TYPEDLINK = "/typedlink/attach";
    public static final String LIST_OBJECT_ATTRIBUTES = "/object/attributes";
    public static final String LIST_FACET_ATTRIBUTES = "/facet/attributes";
    public static final String GET_OBJECT_INFORMATION = "/object/information";
    public static final String DETACH_OBJECT = "/object/detach";
    public static final String UPDATE_FACET = "/facet";
    public static final String DETACH_TYPEDLINK = "/typedlink/detach";
    public static final String UPDATE_OBJECT = "/object/update";
    public static final String DELETE_OBJECT = "/object/delete";
    public static final String LIST_OBJECT_CHILDREN = "/object/children";
    public static final String LIST_INCOMING_TYPEDLINK = "/typedlink/incoming";
    public static final String GET_FACET = "/facet";
    public static final String GET_TYPED_LINK_FACET = "/typedlink/facet/get";
    public static final String LIST_OUTGOING_TYPEDLINK = "/typedlink/outgoing";
    public static final String LIST_DIRECTORIES = "/directory/list";
    public static final String NAME = "Name";
    public static final String CHILDREN = "Children";
    public static final String TYPEDLINK_SPECIFIERS = "TypedLinkSpecifiers";
    public static final String REQUIRED_ALWAYS = "REQUIRED_ALWAYS";
    public static final String LINK_SPECIFIERS = "LinkSpecifiers";
    public static final String ATTRIBUTES = "Attributes";
    public static final String KEY = "Key";
    public static final String VALUE = "Value";
    public static final String CREATE_OR_UPDATE = "CREATE_OR_UPDATE";
    public static final String DELETE = "DELETE";
    public static final String ATTRIBUTE = "attribute";
    public static final String ATTRIBUTE_NAME = "AttributeName";
    public static final String IDENTITY_ATTRIBUTE_VALUES = "IdentityAttributeValues";
    public static final String LINK = "link";
    public static final String USER_ROLE_ASSOCIATION = "USER_ROLE_ASSOCIATION";
    public static final String STRING_VALUE = "StringValue";
    public static final String DETACHED_OBJECT_IDENTIFIER = "DetachedObjectIdentifier";
    public static final String DIRECTORIES = "Directories";
    public static final String DIRECTORY_ARN = "DirectoryArn";
    public static final String SCHEMA_ARN = "SchemaArn";
    public static final String APPLIED_SCHEMA_ARN = "AppliedSchemaArn";
    public static final String SCHEMA_FACETS = "SchemaFacets";
    public static final String UM_USER = "UM_USER";
    public static final String UM_ROLE = "UM_ROLE";
    public static final String UM_USER_ATTRIBUTE = "UM_USER_ATTRIBUTE";
    public static final String USER_PASSWORD = "USER_PASSWORD";
    public static final String SALT_VALUE = "SALT_VALUE";
    public static final String REQUIRE_CHANGE = "REQUIRE_CHANGE";
    public static final String CHANGED_TIME = "CHANGED_TIME";
    public static final String DATE_PATTERN = "EE MMM dd HH:mm:ss z yyyy";



    public static final String PAYLOAD_LIST_DIRECTORIES = "{\"state\": \"ENABLED\"}";
    public static final String PAYLOAD_CREATE_USER_ROLE_LINK = "{\"Facet\": {\"Attributes\": [{\"Name\": \"UM_USER_NAME\", \"RequiredBehavior\": \"REQUIRED_ALWAYS\", \"Type\": \"STRING\"}, {\"Name\": \"UM_USER_TENANT_ID\", \"RequiredBehavior\": \"REQUIRED_ALWAYS\", \"Type\": \"STRING\"}, {\"Name\": \"UM_ROLE_NAME\", \"RequiredBehavior\": \"REQUIRED_ALWAYS\", \"Type\": \"STRING\"}, {\"Name\": \"UM_ROLE_TENANT_ID\", \"RequiredBehavior\": \"REQUIRED_ALWAYS\", \"Type\": \"STRING\"}], \"IdentityAttributeOrder\": [ \"UM_USER_NAME\", \"UM_USER_TENANT_ID\", \"UM_ROLE_NAME\", \"UM_ROLE_TENANT_ID\" ], \"Name\": \"USER_ROLE_ASSOCIATION\"}}";
    public static final String PAYLOAD_CREATE_USER_ATTRIBUTE_LINK = "{\"Facet\":{\"Attributes\":[{\"Name\":\"UM_USER_NAME\", \"RequiredBehavior\":\"REQUIRED_ALWAYS\", \"Type\":\"STRING\"}, {\"Name\":\"UM_TENANT_ID\", \"RequiredBehavior\":\"REQUIRED_ALWAYS\", \"Type\":\"STRING\"}, {\"Name\":\"UM_PROFILE_NAME\", \"RequiredBehavior\":\"REQUIRED_ALWAYS\", \"Type\":\"STRING\"}, {\"Name\":\"UM_ATTR_NAME\", \"RequiredBehavior\":\"REQUIRED_ALWAYS\", \"Type\":\"STRING\"}, {\"Name\":\"UM_ATTR_VALUE\", \"RequiredBehavior\":\"REQUIRED_ALWAYS\", \"Type\":\"STRING\"}], \"IdentityAttributeOrder\":[\"UM_USER_NAME\", \"UM_TENANT_ID\", \"UM_PROFILE_NAME\", \"UM_ATTR_NAME\", \"UM_ATTR_VALUE\"], \"Name\":\"USER_ATTRIBUTE_ASSOCIATION\"}}";
    /**
     * Constant for UTF-8.
     */
    public static final String UTF_8 = "UTF-8";
    public static final String UTC = "UTC";
    public static final String HEX_ARRAY_STRING = "0123456789ABCDEF";
    public static final String HMAC_ALGORITHM = "AWS4-HMAC-SHA256";
    public static final String AWS4_REQUEST = "aws4_request";
    public static final String AWS4 = "AWS4";
    public static final String HMAC_SHA = "HmacSHA256";
    public static final String SHA_ALGORITHM = "SHA-256";
    public static final String DATE_TIME_FORMAT = "yyyyMMdd'T'HHmmss'Z'";
    public static final String DATE_FORMAT = "yyyyMMdd";
    public static final String STRING_FORMAT = "%s %s";
    public static final String ERROR_COULD_NOT_READ_HTTP_ENTITY = "Could not read http entity for response";
    public static final String ERROR_WHILE_PARSING_RESPONSE = "Error while parsing response json";
    public static final String ERROR_WHILE_READING_RESPONSE = "Error while reading response body";
}
