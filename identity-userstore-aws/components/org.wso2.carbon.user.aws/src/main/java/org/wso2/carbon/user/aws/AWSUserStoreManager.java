/*
 * Copyright (c) 2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.user.aws;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.user.api.Properties;
import org.wso2.carbon.user.api.Property;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.aws.util.AWSRestApiActions;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreConfigConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.RoleContext;
import org.wso2.carbon.user.core.jdbc.JDBCRoleContext;
import org.wso2.carbon.user.core.profile.ProfileConfigurationManager;
import org.wso2.carbon.user.core.tenant.Tenant;
import org.wso2.carbon.user.core.util.DatabaseUtil;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.regex.Pattern;
import javax.sql.DataSource;

public class AWSUserStoreManager extends AbstractUserStoreManager {

    private static final Log log = LogFactory.getLog(AWSUserStoreManager.class);
    private static DataSource dataSourceLocal = null;
    private String domain = null;
    private AWSRestApiActions awsActions;
    private String directoryArn;
    private String pathToUsers;
    private String pathToRoles;
    private String appliedSchemaArn;
    private String facetNameOfUser;
    private String facetNameOfRole;
    private String membershipType;
    private String userNameAttribute;
    private String passwordAttribute;
    private String membershipAttribute;
    private String roleNameAttribute;
    private String memberOfAttribute;
    private String groupFacetName;
    private String typedLinkFacetName;
    private String passwordHashMethod;
    private boolean kdcEnabled = false;

    public AWSUserStoreManager() {

    }

    public AWSUserStoreManager(RealmConfiguration realmConfig, int tenantId) throws UserStoreException, IOException, ParseException {

        System.out.println("################################################ AWSUserStoreManager 1111");
        this.realmConfig = realmConfig;
        this.tenantId = tenantId;
        awsActions = new AWSRestApiActions(realmConfig);
        // Set groups read/write configuration
        if (realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.READ_GROUPS_ENABLED) != null) {
            readGroupsEnabled = Boolean.parseBoolean(realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.READ_GROUPS_ENABLED));
        }

        if (realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.WRITE_GROUPS_ENABLED) != null) {
            writeGroupsEnabled = Boolean.parseBoolean(realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.WRITE_GROUPS_ENABLED));
        } else {
            if (!isReadOnly()) {
                writeGroupsEnabled = true;
            }
        }
        if (writeGroupsEnabled) {
            readGroupsEnabled = true;
        }

        // Initialize user roles cache as implemented in AbstractUserStoreManager
        initUserRolesCache();

        setUpAWSDirectory();
    }

    public AWSUserStoreManager(RealmConfiguration realmConfig, Map<String, Object> properties,
                               ClaimManager claimManager, ProfileConfigurationManager profileManager, UserRealm realm, Integer tenantId)
            throws UserStoreException, IOException, ParseException {

        this(realmConfig, tenantId);

        if (log.isDebugEnabled()) {
            log.debug("Started " + System.currentTimeMillis());
        }
        this.claimManager = claimManager;
        this.userRealm = realm;

        dataSource = (DataSource) properties.get(UserCoreConstants.DATA_SOURCE);
        if (dataSource == null) {
            dataSource = DatabaseUtil.getRealmDataSource(realmConfig);
        }
        if (dataSource == null) {
            throw new UserStoreException("User Management Data Source is null");
        }

        doInitialSetup();
        this.persistDomain();
        if (realmConfig.isPrimary()) {
            addInitialAdminData(Boolean.parseBoolean(realmConfig.getAddAdmin()), !isInitSetupDone());
        }

        properties.put(UserCoreConstants.DATA_SOURCE, dataSource);

        if (log.isDebugEnabled()) {
            log.debug("The AWSDataSource being used by AWSUserStoreManager :: " + dataSource.hashCode());
        }

        if (log.isDebugEnabled()) {
            log.debug("Ended " + System.currentTimeMillis());
        }

        domain = realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);
        /*
         * Initialize user roles cache as implemented in AbstractUserStoreManager
         */
        initUserRolesCache();
    }

    public static void setDBDataSource(DataSource source) {

        dataSourceLocal = source;
    }

    /**
     * Checks if the role is existing the role store.
     *
     * @param roleNameWithTenantDomain Rolename with tenant domain.
     * @return Whether the role is existing in role store or not.
     * @throws UserStoreException  If error occurred.
     */
    @Override
    protected boolean doCheckExistingRole(String roleNameWithTenantDomain) throws UserStoreException {

        System.out.println("Inside doCheckExistingRole---------------");
        RoleContext roleContext = createRoleContext(roleNameWithTenantDomain);
        System.out.println("created roleContext");
        String roleName = roleContext.getRoleName();
        System.out.println("roleName" + roleName);

        JSONObject objectChildrens = awsActions.listObjectChildren(directoryArn, pathToRoles);
        if (objectChildrens.get(AWSConstants.CHILDREN) != null) {
            JSONObject childrens = (JSONObject) objectChildrens.get(AWSConstants.CHILDREN);
            for (Object key : childrens.keySet()) {
                String keyValue = key.toString();
                if (keyValue.equals(roleName)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Adds the user to the user store.
     *
     * @param userName              of new user.
     * @param credential            of new user.
     * @param roleList              of new user.
     * @param claims                user claim values.
     * @param profileName           user profile name.
     * @param requirePasswordChange Status to change password.
     * @throws UserStoreException  If error occurred.
     */
    @Override
    public void doAddUser(String userName, Object credential, String[] roleList, Map<String, String> claims,
                          String profileName, boolean requirePasswordChange) throws UserStoreException {

        System.out.println("Inside adding new User method--------------------------------");
        if (!checkUserNameValid(userName)) {
            String errorMsg = realmConfig.getUserStoreProperty(AWSRealmConstants.PROPERTY_USER_NAME_ERROR_MSG);
            if (errorMsg != null) {
                throw new UserStoreException(errorMsg);
            }
            throw new UserStoreException("User name not valid. User name must be a non null string with " +
                    "following format, " + realmConfig.getUserStoreProperty(UserCoreConstants.
                    RealmConfig.PROPERTY_USER_NAME_JAVA_REG_EX));
        }
        if (!checkUserPasswordValid(credential)) {
            String errorMsg = realmConfig.getUserStoreProperty(AWSRealmConstants.PROPERTY_PASSWORD_ERROR_MSG);
            if (errorMsg != null) {
                throw new UserStoreException(errorMsg);
            }
            throw new UserStoreException("Credential not valid. Credential must be a non null string with following " +
                    "format, " + realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_JAVA_REG_EX));
        }
        boolean isExisting = doCheckExistingUser(userName);
        if (isExisting) {
            throw new UserStoreException("User name : " + userName +
                    " exists in the system. Please pick another user name");
        }

        Map<String, String> map = new HashMap<>();
        byte[] passwordToStore = UserCoreUtil.getPasswordToStore(credential, this.realmConfig.getUserStoreProperty
                (AWSRealmConstants.PASSWORD_HASH_METHOD), kdcEnabled);
        System.out.println("password ----------" + new String(passwordToStore));

        map.put(userNameAttribute, userName);
        map.put(passwordAttribute, new String(passwordToStore));
        awsActions.createObject(directoryArn, getPayloadToCreateObject(userName, facetNameOfUser, pathToUsers, map));

        if (log.isDebugEnabled()) {
            log.debug("Added user " + userName + " successfully");
        }

        if(roleList != null && roleList.length > 0) {
            try {
                /* update the user roles */
                String[] users = {userName};
                addUserToRoleList(users, roleList);
                if (log.isDebugEnabled()) {
                    log.debug("Roles are added for user  : " + userName + " successfully.");
                }
            } catch (UserStoreException e) {
                String errorMessage = "User is added. But error while updating role list of user : " + userName;
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e);
                }
                throw new UserStoreException(errorMessage, e);
            }
        }
        System.out.println("Starting to add claims for user-----------");
        if (claims.size() > 0) {
            doSetUserClaimValues(userName, claims, profileName);
        }
    }

    /**
     * Deletes a user by userName from userstore.
     *
     * @param userName of user to delete
     * @throws UserStoreException exception if any occur.
     */
    @Override
    public void doDeleteUser(String userName) throws UserStoreException {

        System.out.println("Inside doDeleteUser----------");
        String selector = pathToUsers + "/" + userName;
        if(membershipType.equals(AWSConstants.LINK)) {
            JSONObject outgoingTypedLinks = awsActions.listOutgoingTypedLinks(directoryArn, getTypedLinkPayload(null, selector));
            if (outgoingTypedLinks.get(AWSConstants.TYPEDLINK_SPECIFIERS) != null) {
                JSONArray typedLinkSpecifiers = (JSONArray) outgoingTypedLinks.get(AWSConstants.TYPEDLINK_SPECIFIERS);
                if (typedLinkSpecifiers.size() > 0) {
                    for (Object typedLinkSpecifier : typedLinkSpecifiers) {
                        JSONObject keyValue = (JSONObject) typedLinkSpecifier;
                        String detachPayload = "{\"TypedLinkSpecifier\": " + keyValue.toJSONString() + "}";
                        System.out.println("detachPayload --" + detachPayload);
                        int statusCode = awsActions.detachTypedLink(directoryArn, detachPayload);
                        if (statusCode != 200) {
                            if (log.isDebugEnabled()) {
                                log.debug("Could not detach typed link from object");
                            }
                        }
                    }
                }
            }
        } else if (membershipType.equals(AWSConstants.ATTRIBUTE)) {
            Map<String, String> map = new HashMap<>();
            JSONObject objectChildrens = awsActions.listObjectChildren(directoryArn, pathToRoles);
            if (objectChildrens.get(AWSConstants.CHILDREN) != null) {
                JSONObject childrens = (JSONObject) objectChildrens.get(AWSConstants.CHILDREN);
                for (Object key : childrens.keySet()) {
                    String keyValue = pathToRoles + "/" + key.toString();
                    String existingUsers = getValueOfAttribute(facetNameOfRole, keyValue, memberOfAttribute);
                    if(existingUsers.contains(userName)) {
                        List<String> list = new LinkedList<>(Arrays.asList(existingUsers.split(",")));
                        list.remove(userName);

                        map.put(memberOfAttribute, String.join(",", list));
                        awsActions.updateObjectAttributes(directoryArn, getPayloadToUpdateObjectAttributes(
                                AWSConstants.CREATE_OR_UPDATE, facetNameOfRole, keyValue, map));
                        map.clear();
                    }
                }
            }
        }
        // Detach object from parent object.
        JSONObject detachObject = awsActions.detachObject(directoryArn,
                getPayloadTodetachObject(userName, pathToUsers));
        if (detachObject.get(AWSConstants.DETACHED_OBJECT_IDENTIFIER) != null) {
            String identifier = "$" + detachObject.get(AWSConstants.DETACHED_OBJECT_IDENTIFIER).toString();
            // Delete object from directory.
            awsActions.deleteObject(directoryArn, identifier);
        }
    }

    /**
     * Changes the password of the user.
     *
     * @param userName      of user to update credentials.
     * @param oldCredential of user.
     * @param newCredential of user to update.
     * @throws UserStoreException exception if any occur.
     */
    @Override
    public void doUpdateCredential(String userName, Object newCredential, Object oldCredential)
            throws UserStoreException {

        this.doUpdateCredentialByAdmin(userName, newCredential);
    }

    /**
     * Update admin user credentials in user store.
     *
     * @param userName      of admin to update credentials.
     * @param newCredential of user to update.
     * @throws UserStoreException exception if any occur.
     */
    @Override
    public void doUpdateCredentialByAdmin(String userName, Object newCredential) throws UserStoreException {

        System.out.println("Inside doUpdateCredentialByAdmin------------------");
        if (!checkUserPasswordValid(newCredential)) {
            String errorMsg = realmConfig.getUserStoreProperty(AWSRealmConstants.PROPERTY_PASSWORD_ERROR_MSG);
            if (errorMsg != null) {
                throw new UserStoreException(errorMsg);
            }

            throw new UserStoreException(
                    "Credential not valid. Credential must be a non null string with following format, "
                            + realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_JAVA_REG_EX));
        }

        Map<String, String> map = new HashMap<>();
        byte[] passwordToStore = UserCoreUtil.getPasswordToStore(newCredential, passwordHashMethod, kdcEnabled);

        map.put(passwordAttribute, new String(passwordToStore));
        awsActions.updateObjectAttributes(directoryArn, getPayloadToUpdateObjectAttributes(
                AWSConstants.CREATE_OR_UPDATE, facetNameOfUser, pathToUsers + "/" + userName, map));
    }

    /**
     * Check whether the user is exists in user store.
     *
     * @param userName given to check.
     * @return boolean true or false respectively for user exists or not.
     * @throws UserStoreException  exception if any occur.
     */
    @Override
    protected boolean doCheckExistingUser(String userName) throws UserStoreException {

        System.out.println("Inside doCheckExistingUser method");
        JSONObject objectChildrens = awsActions.listObjectChildren(directoryArn, pathToUsers);
        if (objectChildrens.get(AWSConstants.CHILDREN) != null) {
            JSONObject childrens = (JSONObject) objectChildrens.get(AWSConstants.CHILDREN);
            for (Object key : childrens.keySet()) {
                String keyValue = key.toString();
                if (keyValue.equals(userName)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Adds a role to the role store.
     *
     * @param roleName of new role.
     * @param userList of new role to add.
     * @param shared   status of whether the role is shared or not.
     * @throws UserStoreException if any exception occurred.
     */
    @Override
    public void doAddRole(String roleName, String[] userList, boolean shared) throws UserStoreException {
        System.out.println("Inside doAddRole method");
        boolean isExisting = doCheckExistingRole(roleName);
        if (isExisting) {
            throw new UserStoreException("Role name : " + roleName +
                    " exists in the system. Please pick another role name");
        }

        Map<String, String> map = new HashMap<>();
        map.put(roleNameAttribute, roleName);
        awsActions.createObject(directoryArn, getPayloadToCreateObject(roleName, facetNameOfRole, pathToRoles, map));
        System.out.println("Starting to add roles to user list");

        if (userList != null && userList.length > 0) {
            String[] roleList = {roleName};
            addUserToRoleList(userList, roleList);
        }
    }

    /**
     * Deletes a role by role name from the role store.
     *
     * @param roleName to delete from user store
     * @throws UserStoreException if any exception occurred
     */
    @Override
    public void doDeleteRole(String roleName) throws UserStoreException {

        System.out.println("Inside doDeleteRole----------");
        String selector = pathToRoles +"/" + roleName;
        if(membershipType.equals(AWSConstants.LINK)) {
            JSONObject outgoingTypedLinks = awsActions.listIncomingTypedLinks(directoryArn, listIncomingTypedLinksPayload(null, selector));
            if (outgoingTypedLinks.get(AWSConstants.LINK_SPECIFIERS) != null) {
                JSONArray linkSpecifiers = (JSONArray) outgoingTypedLinks.get(AWSConstants.LINK_SPECIFIERS);
                for (Object linkSpecifier : linkSpecifiers) {
                    JSONObject keyValue = (JSONObject) linkSpecifier;
                    String detachPayload = "{\"TypedLinkSpecifier\": " + keyValue.toJSONString() + "}";
                    int statusCode = awsActions.detachTypedLink(directoryArn, detachPayload);
                    if (statusCode != 200) {
                        if (log.isDebugEnabled()) {
                            log.debug("Could not detach typed link from object");
                        }
                    }
                }
            }
        } else if(membershipType.equals(AWSConstants.ATTRIBUTE)){
            Map<String, String> map = new HashMap<>();
            JSONObject objectChildrens = awsActions.listObjectChildren(directoryArn, pathToUsers);
            if (objectChildrens.get(AWSConstants.CHILDREN) != null) {
                JSONObject childrens = (JSONObject) objectChildrens.get(AWSConstants.CHILDREN);
                for (Object key : childrens.keySet()) {
                    String keyValue = pathToUsers + "/" + key.toString();
                    String existingRoles = getValueOfAttribute(facetNameOfUser, keyValue, membershipAttribute);
                    if(existingRoles.contains(roleName)) {
                        List<String> list = new LinkedList<>(Arrays.asList(existingRoles.split(",")));
                        list.remove(roleName);

                        map.put(membershipAttribute, String.join(",", list));
                        awsActions.updateObjectAttributes(directoryArn, getPayloadToUpdateObjectAttributes(
                                AWSConstants.CREATE_OR_UPDATE, facetNameOfUser, keyValue, map));
                        map.clear();
                    }
                }
            }
        }

        // Detach object from parent object.
        JSONObject detachObject = awsActions.detachObject(directoryArn, getPayloadTodetachObject(roleName, pathToRoles));
        if (detachObject.get(AWSConstants.DETACHED_OBJECT_IDENTIFIER) != null) {
            String identifier = "$" + detachObject.get(AWSConstants.DETACHED_OBJECT_IDENTIFIER).toString();
            // Delete object from directory.
            awsActions.deleteObject(directoryArn, identifier);
        }
    }

    /**
     * Updates the role name in the role store.
     *
     * @param roleName    to update.
     * @param newRoleName to be updated.
     * @throws UserStoreException if any exception occurred.
     */
    @Override
    public void doUpdateRoleName(String roleName, String newRoleName) throws UserStoreException {

        System.out.println("Inside doUpdateRoleName------------------");

        JDBCRoleContext ctx = (JDBCRoleContext) createRoleContext(roleName);
        roleName = ctx.getRoleName();
        boolean isShared = false;
        if (ctx.isShared()) {
            isShared = true;
        }
        List<String> tempList = new ArrayList<>();

        // Get user list of role
        String[] userListWithDomain = doGetUserListOfRole(roleName, "*");
        for (String userList : userListWithDomain) {
            String[] removedUserNames = userList.split(CarbonConstants.DOMAIN_SEPARATOR);
            if (removedUserNames.length > 1) {
                userList = removedUserNames[1];
            }
            tempList.add(userList);
        }
        String[] users = tempList.toArray(new String[tempList.size()]);
        // Delete old role
        doDeleteRole(roleName);

        // Add new role and Add users to the new role
        doAddRole(newRoleName, users, isShared);
    }

    /**
     * Authenticates a user given the user name and password against the user store.
     *
     * @param userName   of authenticating user.
     * @param credential include user password of authenticating user.
     * @return boolean if authenticate fail or not.
     * @throws UserStoreException If any exception occurred.
     */
    @Override
    public boolean doAuthenticate(String userName, Object credential) throws UserStoreException {

        System.out.println("Inside doAuthenticate-----------");
        boolean debug = log.isDebugEnabled();
        userName = userName.trim();
        if (StringUtils.isEmpty(userName) || credential == null) {
            return false;
        }

        if (debug) {
            log.debug("Authenticating user " + userName);
        }

        String selector = pathToUsers + "/" + userName;
        String storedPassword = getValueOfAttribute(facetNameOfUser, selector, passwordAttribute);
        byte[] password = UserCoreUtil.getPasswordToStore(credential, passwordHashMethod, kdcEnabled);

        return (storedPassword != null) && (storedPassword.equals(new String(password)));
    }

    /**
     * Lists the users in the user store.
     *
     * @param filter       to filter the search.
     * @param maxItemLimit to display per page.
     * @return String[] of users.
     * @throws UserStoreException if any exception occurred.
     */
    @Override
    protected String[] doListUsers(String filter, int maxItemLimit) throws UserStoreException {

        System.out.println("Inside of doListUsers method------------------");

        String name;
        int givenMax;
        String[] users = new String[0];
        List<String> tempList = new LinkedList<>();

        if (maxItemLimit == 0) {
            return users;
        }
        try {
            givenMax = Integer.parseInt(realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_MAX_USER_LIST));
        } catch (Exception e) {
            givenMax = UserCoreConstants.MAX_USER_ROLE_LIST;

            if (log.isDebugEnabled()) {
                log.debug("Realm configuration maximum not set : Using User Core Constant value instead!", e);
            }
        }
        if (maxItemLimit < 0 || maxItemLimit > givenMax) {
            maxItemLimit = givenMax;
        }

        JSONObject objectChildrens = awsActions.listObjectChildren(directoryArn, pathToUsers);
        if (objectChildrens.get(AWSConstants.CHILDREN) != null) {
            JSONObject childrens = (JSONObject) objectChildrens.get(AWSConstants.CHILDREN);
            for (Object key : childrens.keySet()) {
                String keyValue = key.toString();
                if (matchFilter(keyValue, filter)) {
                    name = UserCoreUtil.addDomainToName(keyValue, domain);
                    tempList.add(name);
                }
            }
        }
        int usersCount = tempList.size();
        if (usersCount > 0) {
            users = tempList.toArray(new String[tempList.size()]);
        }
        Arrays.sort(users);
        if (usersCount < maxItemLimit) {
            maxItemLimit = usersCount;
        }
        users = Arrays.copyOfRange(users, 0, maxItemLimit);

        for (int i = 0; i < users.length; i++) {
            System.out.println(users[i]);
        }

        return users;
    }

    /**
     * Match strings against a pattern.
     *
     * @param text String that need to be matched.
     * @param filter Pattern.
     * @return Whether the provided text is matched against the pattern or not.
     */
    private boolean matchFilter(String text, String filter) {

        System.out.println("matchFilter --" + text + "---------" + filter);
        if (text == null || filter == null) return true;

        StringBuilder builder = new StringBuilder(".*");

        for (StringTokenizer st = new StringTokenizer(filter, "%*", true); st.hasMoreTokens(); ) {
            String token = st.nextToken();
            switch (token) {
                case "?":
                    builder.append(".");
                    break;
                case "*":
                    builder.append(".*");
                    break;
                default:
                    builder.append(Pattern.quote(token));
                    break;
            }
        }
        builder.append(".*");
        return text.matches(builder.toString());
    }

    /**
     * Get the role names in the roles store.
     *
     * @param filter       to filter the search.
     * @param maxItemLimit to display per page.
     * @return String[] of roles.
     * @throws UserStoreException if any exception occurred.
     */
    @Override
    public String[] doGetRoleNames(String filter, int maxItemLimit) throws UserStoreException {

        System.out.println("Inside doGetRoleNames----");
        int givenMax;
        String name;
        String[] roles = new String[0];
        List<String> tempList = new LinkedList<>();

        if (maxItemLimit == 0) {
            return roles;
        }

        try {
            givenMax = Integer.parseInt(realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_MAX_ROLE_LIST));
        } catch (Exception e) {
            givenMax = UserCoreConstants.MAX_USER_ROLE_LIST;

            if (log.isDebugEnabled()) {
                log.debug("Realm configuration maximum not set : Using User Core Constant value instead!", e);
            }
        }

        if (maxItemLimit < 0 || maxItemLimit > givenMax) {
            maxItemLimit = givenMax;
        }

        JSONObject objectChildrens = awsActions.listObjectChildren(directoryArn, pathToRoles);
        if (objectChildrens.get(AWSConstants.CHILDREN) != null) {
            JSONObject childrens = (JSONObject) objectChildrens.get(AWSConstants.CHILDREN);
            for (Object key : childrens.keySet()) {
                String keyValue = key.toString();
                if (matchFilter(keyValue, filter)) {
                    name = UserCoreUtil.addDomainToName(keyValue, domain);
                    tempList.add(name);
                }
            }
        }
        int rolesCount = tempList.size();
        if (rolesCount > 0) {
            roles = tempList.toArray(new String[tempList.size()]);
        }
        Arrays.sort(roles);
        if (rolesCount < maxItemLimit) {
            maxItemLimit = rolesCount;
        }
        roles = Arrays.copyOfRange(roles, 0, maxItemLimit);
        for (int i = 0; i < roles.length; i++) {
            System.out.println(roles[i]);
        }

        return roles;
    }

//    /**
//     * Checks if user is existing in the user store.
//     *
//     * @param userName Name of the user.
//     * @return user is exist or not in user store.
//     * @throws UserStoreException if any exception occurred.
//     */
//    @Override
//    public boolean isExistingUser(String userName) throws UserStoreException {
//
//        System.out.println("Inside isExistingUser method");
//        return doCheckExistingUser(userName);
//    }

//    /**
//     * Check if role is existing in the role store.
//     *
//     * @param roleName Name of the role.
//     * @return role is exist or not in role store.
//     * @throws UserStoreException if any exception occurred.
//     */
//    @Override
//    public boolean isExistingRole(String roleName) throws UserStoreException {
//
//        return doCheckExistingRole(roleName);
//    }

    /**
     * Get the list of users mapped to a role.
     *
     * @param filter   to filter the search.
     * @param roleName to search for users.
     * @return String[] of users.
     * @throws UserStoreException if any exception occurred.
     */
    @Override
    public String[] doGetUserListOfRole(String roleName, String filter) throws UserStoreException {

        System.out.println("Inside doGetUserListOfRole---------------");
        String[] users = new String[0];
        List<String> tempList = new LinkedList<>();
        RoleContext roleContext = createRoleContext(roleName);
        roleName = roleContext.getRoleName();

        String selector = pathToRoles + "/" + roleName;
        switch (membershipType) {
            case AWSConstants.LINK:
                JSONObject links = awsActions.listIncomingTypedLinks(directoryArn,
                        listIncomingTypedLinksPayload(typedLinkFacetName, selector));
                JSONArray linkSpecifiers = (JSONArray) links.get(AWSConstants.LINK_SPECIFIERS);
                if (linkSpecifiers.size() > 0) {
                    for (Object linkSpecifier : linkSpecifiers) {
                        JSONObject keyValue = (JSONObject) linkSpecifier;
                        JSONArray attributes = (JSONArray) keyValue.get(AWSConstants.IDENTITY_ATTRIBUTE_VALUES);
                        for (Object attribute : attributes) {
                            JSONObject key = (JSONObject) attribute;
                            Object attributeName = key.get(AWSConstants.ATTRIBUTE_NAME);
                            JSONObject attributeValue = (JSONObject) key.get(AWSConstants.VALUE);
                            if (attributeName.equals(userNameAttribute)) {
                                tempList.add(UserCoreUtil.addDomainToName(attributeValue.get(
                                        AWSConstants.STRING_VALUE).toString(), domain));
                            }
                        }
                    }
                }
                break;
            case AWSConstants.ATTRIBUTE:
                String[] userList = new String[0];
                String existingUsers = getValueOfAttribute(facetNameOfRole, selector, memberOfAttribute);
                if(StringUtils.isNotEmpty(existingUsers)) {
                    userList = existingUsers.split(",");
                }
                for (String user : userList) {
                    tempList.add(UserCoreUtil.addDomainToName(user, domain));
                }
                break;
        }

        if (tempList.size() > 0) {
            users = tempList.toArray(new String[tempList.size()]);
        }

        for (int i = 0; i < users.length; i++) {
            System.out.println(users[i]);
        }

        return users;
    }

    /**
     * Gets the external role list of a user.
     *
     * @param userName of user to get role list.
     * @param filter   if any filtering apply.
     * @return String[] of rolelist of user.
     * @throws UserStoreException if any error occurred.
     */
    @Override
    public String[] doGetExternalRoleListOfUser(String userName, String filter) throws UserStoreException {

        System.out.println("Inside doGetExternalRoleListOfUser---------------");
        String[] roles = new String[0];
        List<String> tempList = new LinkedList<>();
        String selector = pathToUsers + "/" + userName;
        switch (membershipType) {
            case AWSConstants.LINK:
                JSONObject outgoingTypedLinks = awsActions.listOutgoingTypedLinks(directoryArn,
                        getTypedLinkPayload(typedLinkFacetName, selector));
                System.out.println(selector);
                if (outgoingTypedLinks != null) {
                    JSONArray linkSpecifiers = (JSONArray) outgoingTypedLinks.get(AWSConstants.TYPEDLINK_SPECIFIERS);
                    if (linkSpecifiers.size() > 0) {
                        for (Object linkSpecifier : linkSpecifiers) {
                            JSONObject keyValue = (JSONObject) linkSpecifier;
                            System.out.println(keyValue);
                            JSONArray attributes = (JSONArray) keyValue.get(AWSConstants.IDENTITY_ATTRIBUTE_VALUES);
                            for (Object attribute : attributes) {
                                JSONObject key = (JSONObject) attribute;
                                Object attributeName = key.get(AWSConstants.ATTRIBUTE_NAME);
                                JSONObject attributeValue = (JSONObject) key.get(AWSConstants.VALUE);
                                if (attributeName.equals(roleNameAttribute)) {
                                    tempList.add(attributeValue.get(AWSConstants.STRING_VALUE).toString());
                                }
                                System.out.println(attributeName);
                                System.out.println(attributeValue.get(AWSConstants.STRING_VALUE));
                            }
                        }
                    }
                }
                break;
            case AWSConstants.ATTRIBUTE:
                String[] roleList = new String[0];
                String existingRoles = getValueOfAttribute(facetNameOfUser, selector, membershipAttribute);
                if(StringUtils.isNotEmpty(existingRoles)) {
                    roleList = existingRoles.split(",");
                }
                for (String role : roleList) {
                    tempList.add(UserCoreUtil.addDomainToName(role, domain));
                }
                break;
        }

        if (tempList.size() > 0) {
            roles = tempList.toArray(new String[tempList.size()]);
        }
        System.out.println("Role list length " + roles.length);
        for (int i = 0; i < roles.length; i++) {
            System.out.println(roles[i]);
        }

        return roles;
    }

    /**
     * Update the role list of a user.
     *
     * @param userName     of user to update.
     * @param deletedRoles send this param fill with if want to remove role from user.
     * @param newRoles     send this paramfill with if want to add role to user.
     * @throws UserStoreException if any error occurred.
     */
    @Override
    public void doUpdateRoleListOfUser(String userName, String[] deletedRoles, String[] newRoles)
            throws UserStoreException {

        System.out.println("Inside doUpdateRoleListOfUser------------" + userName);
        String[] userNames = userName.split(CarbonConstants.DOMAIN_SEPARATOR);
        if (userNames.length > 1) {
            userName = userNames[1];
        }
        Map<String, String> map = new HashMap<>();
        if (deletedRoles != null && deletedRoles.length > 0) {
            System.out.println("Inside of deletedRoles-----------" + deletedRoles.length);
            for (String roleName : deletedRoles) {
                String selector = pathToRoles + "/" + roleName.trim();
                if(membershipType.equals(AWSConstants.LINK)) {
                    JSONObject incomingTypedLinks = awsActions.listIncomingTypedLinks(directoryArn,
                            listIncomingTypedLinksPayload(typedLinkFacetName, selector));
                    if (incomingTypedLinks.get(AWSConstants.LINK_SPECIFIERS) != null) {
                        JSONArray linkSpecifiers = (JSONArray) incomingTypedLinks.get(AWSConstants.LINK_SPECIFIERS);
                        for (Object linkSpecifier : linkSpecifiers) {
                            JSONObject keyValue = (JSONObject) linkSpecifier;
                            JSONArray identityAttributeValues = (JSONArray) keyValue.get(
                                    AWSConstants.IDENTITY_ATTRIBUTE_VALUES);
                            boolean userNameFound = false;
                            for (Object attribute : identityAttributeValues) {
                                JSONObject key = (JSONObject) attribute;
                                Object attributeName = key.get(AWSConstants.ATTRIBUTE_NAME);
                                JSONObject attributeValue = (JSONObject) key.get(AWSConstants.VALUE);
                                if (attributeName.equals(userNameAttribute)
                                        && attributeValue.get(AWSConstants.STRING_VALUE).equals(userName)) {
                                    userNameFound = true;
                                    break;
                                }
                                System.out.println("----------------------------------");
                            }
                            if (userNameFound) {
                                String detachPayload = "{\"TypedLinkSpecifier\": " + keyValue.toJSONString() + "}";
                                int statusCode = awsActions.detachTypedLink(directoryArn, detachPayload);
                                if (statusCode != 200) {
                                    if (log.isDebugEnabled()) {
                                        log.debug("Could not detach typed link from object");
                                    }
                                }
                                break;
                            }
                        }
                    }
                } else if(membershipType.equals(AWSConstants.ATTRIBUTE)) {
                    String existingUsers = getValueOfAttribute(facetNameOfRole, selector, memberOfAttribute);
                    if(existingUsers.contains(userName)) {
                        List<String> list = new LinkedList<>(Arrays.asList(existingUsers.split(",")));
                        list.remove(userName);

                        map.put(memberOfAttribute, String.join(",", list));
                        awsActions.updateObjectAttributes(directoryArn, getPayloadToUpdateObjectAttributes(
                                AWSConstants.CREATE_OR_UPDATE, facetNameOfRole, selector, map));
                        map.clear();
                    }
                }
            }

            if (membershipType.equals(AWSConstants.ATTRIBUTE)) {
                String selector = pathToUsers + "/" + userName;
                String existingRoles = getValueOfAttribute(facetNameOfUser, selector, membershipAttribute);
                if (StringUtils.isNotEmpty(existingRoles)) {
                    List<String> list = new LinkedList<>(Arrays.asList(existingRoles.split(",")));
                    list.removeAll(Arrays.asList(deletedRoles));

                    map.put(membershipAttribute, String.join(",", list));
                    awsActions.updateObjectAttributes(directoryArn, getPayloadToUpdateObjectAttributes(
                            AWSConstants.CREATE_OR_UPDATE, facetNameOfUser, selector, map));
                    map.clear();
                }
            }
        }

        if (newRoles != null && newRoles.length > 0) {
            System.out.println("Adding role to use addRoleToUsersList----------------newRoles-----" + newRoles.length + "-----------");
            String[] userList = {userName};
            addUserToRoleList(userList, newRoles);
        }

    }

    /**
     * Update the user list mapped to a role.
     *
     * @param roleName     of user to update.
     * @param deletedUsers send this param fill with if want to remove user from role.
     * @param newUsers     send this paramfill with if want to add user to role.
     * @throws UserStoreException if any error occurred.
     */
    @Override
    public void doUpdateUserListOfRole(String roleName, String[] deletedUsers, String[] newUsers)
            throws UserStoreException {

        System.out.println("Inside doUpdateUserListOfRole-------------------" + roleName);
        Map<String, String> map = new HashMap<>();
        if (deletedUsers != null && deletedUsers.length > 0) {
            System.out.println("Inside of deletedUsers-----------" + deletedUsers.length);
            for (String userName : deletedUsers) {
                String selector = pathToUsers + "/" + userName.trim();
                if (membershipType.equals(AWSConstants.LINK)) {
                    JSONObject outgoingTypedLinks = awsActions.listOutgoingTypedLinks(directoryArn,
                            getTypedLinkPayload(typedLinkFacetName, selector));
                    if (outgoingTypedLinks.get(AWSConstants.TYPEDLINK_SPECIFIERS) != null) {
                        JSONArray typedLinkSpecifiers = (JSONArray) outgoingTypedLinks.get(
                                AWSConstants.TYPEDLINK_SPECIFIERS);
                        for (Object typedLinkSpecifier : typedLinkSpecifiers) {
                            JSONObject keyValue = (JSONObject) typedLinkSpecifier;
                            JSONArray identityAttributeValues = (JSONArray) keyValue.get(
                                    AWSConstants.IDENTITY_ATTRIBUTE_VALUES);
                            boolean roleFound = false;
                            for (Object attribute : identityAttributeValues) {
                                JSONObject key = (JSONObject) attribute;
                                Object attributeName = key.get(AWSConstants.ATTRIBUTE_NAME);
                                JSONObject attributeValue = (JSONObject) key.get(AWSConstants.VALUE);
                                if (attributeName.equals(roleNameAttribute) &&
                                        attributeValue.get(AWSConstants.STRING_VALUE).equals(roleName)) {
                                    roleFound = true;
                                    break;
                                }

                                System.out.println("----------------------------------");
                            }
                            if (roleFound) {
                                System.out.println("inside userNameFound && userTenantIdFound && roleFound");
                                String detachPayload = "{\"TypedLinkSpecifier\": " + keyValue.toJSONString() + "}";
                                int statusCode = awsActions.detachTypedLink(directoryArn, detachPayload);
                                if (statusCode != 200) {
                                    if (log.isDebugEnabled()) {
                                        log.debug("Could not detach typed link from object");
                                    }
                                }
                                break;
                            }
                        }
                        System.out.println("After break--------------------");
                    }
                } else if(membershipType.equals(AWSConstants.ATTRIBUTE)) {
                    String existingRoles = getValueOfAttribute(facetNameOfUser, selector, membershipAttribute);
                    if(existingRoles.contains(roleName)) {
                        List<String> list = new LinkedList<>(Arrays.asList(existingRoles.split(",")));
                        list.remove(roleName);

                        map.put(membershipAttribute, String.join(",", list));
                        awsActions.updateObjectAttributes(directoryArn, getPayloadToUpdateObjectAttributes(
                                AWSConstants.CREATE_OR_UPDATE, facetNameOfUser, selector, map));
                        map.clear();
                    }
                }
            }

            if (membershipType.equals(AWSConstants.ATTRIBUTE)) {
                String selector = pathToRoles + "/" + roleName;
                String existingUsers = getValueOfAttribute(facetNameOfRole, selector, memberOfAttribute);
                if (StringUtils.isNotEmpty(existingUsers)) {
                    List<String> list = new LinkedList<>(Arrays.asList(existingUsers.split(",")));
                    list.removeAll(Arrays.asList(deletedUsers));

                    map.put(memberOfAttribute, String.join(",", list));
                    awsActions.updateObjectAttributes(directoryArn, getPayloadToUpdateObjectAttributes(
                            AWSConstants.CREATE_OR_UPDATE, facetNameOfRole, selector, map));
                    map.clear();
                }
            }
        }

        if (newUsers != null && newUsers.length > 0) {
            System.out.println("Adding role to use addRoleToUsersList-----newUsers----------------"+newUsers.length);
            String[] roleList = {roleName};
            addUserToRoleList(newUsers, roleList);
        }
    }

    /**
     * Create context of given role.
     *
     * @param roleName Role name to create context.
     * @return RoleContext created for given role.
     */
    @Override
    protected RoleContext createRoleContext(String roleName) {

        System.out.println("Inside createRoleContext----------");
        JDBCRoleContext searchCtx = new JDBCRoleContext();
        String[] roleNameParts = roleName.split(UserCoreConstants.TENANT_DOMAIN_COMBINER);
        int tenantId;
        if (roleNameParts.length > 1) {
            tenantId = Integer.parseInt(roleNameParts[1]);
            searchCtx.setTenantId(tenantId);
        } else {
            tenantId = this.tenantId;
            searchCtx.setTenantId(tenantId);
        }

        if (tenantId != this.tenantId) {
            searchCtx.setShared(true);
        }
        searchCtx.setRoleName(roleNameParts[0]);
        return searchCtx;
    }

    /**
     * Get realm configuration.
     *
     * @return RealmConfiguration of logged in users.
     */
    @Override
    public RealmConfiguration getRealmConfiguration() {

        return this.realmConfig;
    }

    /**
     * Get user list from provided properties.
     *
     * @param property    Property name.
     * @param value       of property name.
     * @param profileName where property belongs to.
     * @return String[] of users.
     */
    @Override
    public String[] getUserListFromProperties(String property, String value, String profileName)
            throws UserStoreException {

        System.out.println("Inside getUserListFromProperties---------------");
        if (StringUtils.isEmpty(property) || StringUtils.isEmpty(value)) {
            return new String[0];
        }

        List<String> userList = new ArrayList<>();
        JSONObject objectChildrens = awsActions.listObjectChildren(directoryArn, pathToUsers);
        if (objectChildrens.get(AWSConstants.CHILDREN) != null) {
            JSONObject childrens = (JSONObject) objectChildrens.get(AWSConstants.CHILDREN);
            for (Object key : childrens.keySet()) {
                String keyValue = pathToUsers + "/" + key.toString();
                JSONObject objectAttributes = awsActions.listObjectAttributes(directoryArn,
                        listObjectAttributesPayload(facetNameOfUser, keyValue));
                JSONArray attributes = (JSONArray) objectAttributes.get(AWSConstants.ATTRIBUTES);
                for (Object attribute : attributes) {
                    JSONObject keyVal = (JSONObject) attribute;
                    String propertyName = ((JSONObject) keyVal.get(AWSConstants.KEY)).get(AWSConstants.NAME).toString();
                    String propertyValue = ((JSONObject) keyVal.get(AWSConstants.VALUE))
                            .get(AWSConstants.STRING_VALUE).toString();
                    if(propertyName.equals(property) && propertyValue.equals(value)) {
                        userList.add(key.toString());
                    }
                }

            }
        }

        return userList.toArray(new String[userList.size()]);
    }

    /**
     * Get shared role names of user store.
     *
     * @param tenantDomain of currently logged in.
     * @param filter       to filter the search.
     * @param maxItemLimit to display per page.
     * @return String[] of shared roles.
     * @throws UserStoreException if any exception occurred.
     */
    @Override
    protected String[] doGetSharedRoleNames(String tenantDomain, String filter, int maxItemLimit)
            throws UserStoreException {

        throw new UserStoreException("doGetSharedRoleNames not implemented for AWSUserStoreManager");
    }

    /**
     * Check whether the user in given role.
     *
     * @param userName to filter the search.
     * @param roleName to display per page.
     * @return boolean status.
     * @throws UserStoreException if any exception occurred.
     */
    @Override
    public boolean doCheckIsUserInRole(String userName, String roleName) throws UserStoreException {

        System.out.println("Inside doCheckIsUserInRole-----------");
        String[] roles = doGetExternalRoleListOfUser(userName, "*");
        if (roles != null) {
            for (String role : roles) {
                if (role.equalsIgnoreCase(roleName)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Get all shared role list of user.
     *
     * @param userName     of user to get shared role list.
     * @param filter       if any filter.
     * @param tenantDomain of currently logged in.
     * @throws UserStoreException if any exception occurred.
     */
    @Override
    protected String[] doGetSharedRoleListOfUser(String userName, String tenantDomain, String filter)
            throws UserStoreException {

        throw new UserStoreException("doGetSharedRoleListOfUser not implemented for AWSUserStoreManager");
    }

    /**
     * We do not have multiple profile support with AWS.
     *
     * @return String[] of profile names.
     * @throws UserStoreException if any exception occurred.
     */
    @Override
    public String[] getAllProfileNames() throws UserStoreException {

        return new String[]{UserCoreConstants.DEFAULT_PROFILE};
    }

    /**
     * Check the status if read only.
     *
     * @return boolean status.
     * @throws UserStoreException if any exception occurred.
     */
    @Override
    public boolean isReadOnly() throws UserStoreException {

        return "true".equalsIgnoreCase(realmConfig.getUserStoreProperty(
                UserCoreConstants.RealmConfig.PROPERTY_READ_ONLY));
    }

    /**
     * get user id of given user
     *
     * @param username to find userId
     * @return int userId
     * @throws UserStoreException if any exception occurred
     */
    @Override
    public int getUserId(String username) throws UserStoreException {

        throw new UserStoreException("Invalid operation");
    }

    /**
     * Get tenantId of given user.
     *
     * @param username to find tenantId.
     * @return int tenantId.
     */
    @Override
    public int getTenantId(String username) throws UserStoreException {

        throw new UserStoreException("Invalid operation");
    }

    /**
     * Get currently logged in tenantId.
     *
     * @return int tenantId.
     */
    @Override
    public int getTenantId() {

        return this.tenantId;
    }

    /**
     * Get properties of given tenant.
     *
     * @param tenant to  search for properties.
     * @return Map of properties.
     * @throws UserStoreException if any exception occurred.
     */
    @Override
    public Map<String, String> getProperties(org.wso2.carbon.user.api.Tenant tenant)
            throws org.wso2.carbon.user.api.UserStoreException {

        return getProperties((Tenant) tenant);
    }

    /**
     * This method is to check whether multiple profiles are allowed with a particular user-store.
     * Currently, AWS user store allows multiple profiles. Hence return true.
     *
     * @return Boolean status of multiple profile.
     */
    @Override
    public boolean isMultipleProfilesAllowed() {

        return false;
    }

    @Override
    public void addRememberMe(String userName, String token) throws org.wso2.carbon.user.api.UserStoreException {

        throw new UserStoreException("addRememberMe not implemented for AWSUserStoreManager");
    }

    @Override
    public boolean isValidRememberMeToken(String userName, String token)
            throws org.wso2.carbon.user.api.UserStoreException {

        throw new UserStoreException("isValidRememberMeToken not implemented for AWSUserStoreManager");
    }

    /**
     * Check whether the bulk import support or not.
     *
     * @return boolean status.
     */
    @Override
    public boolean isBulkImportSupported() {

        return Boolean.valueOf(realmConfig.getUserStoreProperty("IsBulkImportSupported"));
    }

    /**
     * Set user claim value of registered user in user store.
     *
     * @param userName    of registered user.
     * @param claimValue  of user to set.
     * @param claimURI    of user claim.
     * @param profileName of user claims belongs to.
     * @throws UserStoreException if any error occurred.
     */
    @Override
    public void doSetUserClaimValue(String userName, String claimURI, String claimValue, String profileName)
            throws UserStoreException {

        System.out.println("Inside doSetUserClaimValue-------------------");
        // if user name contains domain name, remove domain name
        String[] userNames = userName.split(CarbonConstants.DOMAIN_SEPARATOR);
        if (userNames.length > 1) {
            userName = userNames[1];
        }

        boolean debug = log.isDebugEnabled();
        if (debug) {
            log.debug("Processing user claims");
        }
        Map<String, String> map = new HashMap<>();

        if (debug) {
            log.debug("Claim URI: " + claimURI);
        }
        System.out.println("claimURI----------" + claimURI);
        String attributeName;
        try {
            attributeName = getClaimAtrribute(claimURI, userName, null);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            String errorMessage = "Error in obtaining claim mapping.";
            throw new UserStoreException(errorMessage, e);
        }

        if (debug) {
            log.debug("Mapped attribute: " + attributeName);
            log.debug("Attribute value: " + claimValue);
        }
        System.out.println("Mapped attribute: " + attributeName);
        System.out.println("Attribute value: " + claimValue);
        map.put(attributeName, claimValue);

        if (!isFacetAttributeExist(facetNameOfUser, attributeName)) {
            System.out.println("facet is not exist");
            awsActions.updateFacet(appliedSchemaArn, getPayloadToupdateFacet(facetNameOfUser,
                    Collections.singletonList(attributeName)));
        }

        awsActions.updateObjectAttributes(directoryArn, getPayloadToUpdateObjectAttributes(
                AWSConstants.CREATE_OR_UPDATE, facetNameOfUser, pathToUsers + "/" + userName, map));
        map.clear();
    }

    /**
     * Set user claim values of registered user in user store.
     *
     * @param userName    of registered user.
     * @param claims      of user to set.
     * @param profileName of user claims belongs to.
     * @throws UserStoreException if any error occurred.
     */
    @Override
    public void doSetUserClaimValues(String userName, Map<String, String> claims, String profileName)
            throws UserStoreException {

        System.out.println("inside doSetUserClaimValues---------");
        System.out.println("Processing user claims"+claims.size());
        boolean debug = log.isDebugEnabled();
        if(debug) {
            log.debug("Processing user claims");
        }
        Map<String, String> map = new HashMap<>();
        List<String> attributes = new LinkedList<>();
        for (Map.Entry<String, String> entry : claims.entrySet()) {
            // needs to get attribute name from claim mapping
            String claimURI = entry.getKey();

            if (debug) {
                log.debug("Claim URI: " + claimURI);
            }
            System.out.println("claimURI----------"+claimURI);
            String attributeName;
            try {
                attributeName = getClaimAtrribute(claimURI, userName, null);
            } catch (org.wso2.carbon.user.api.UserStoreException e) {
                throw new UserStoreException("Error in obtaining claim mapping.", e);
            }

            if (debug) {
                log.debug("Mapped attribute: " + attributeName);
                log.debug("Attribute value: " + claims.get(entry.getKey()));
            }
            System.out.println("Mapped attribute: " + attributeName);
            System.out.println("Attribute value: " + claims.get(entry.getKey()));
            map.put(attributeName, claims.get(entry.getKey()));
            if (!isFacetAttributeExist(facetNameOfUser, attributeName)) {
                attributes.add(attributeName);
            }
        }
        if (attributes.size() > 0) {
            System.out.println("updating facet");
            awsActions.updateFacet(appliedSchemaArn, getPayloadToupdateFacet(facetNameOfUser, attributes));
        }

        awsActions.updateObjectAttributes(directoryArn, getPayloadToUpdateObjectAttributes(
                AWSConstants.CREATE_OR_UPDATE, facetNameOfUser, pathToUsers + "/" + userName, map));
        map.clear();
    }

    /**
     * delete user claim value of given user claim
     *
     * @param userName    of user
     * @param claimURI    to delete from user
     * @param profileName where claim belongs to
     * @throws UserStoreException if error occurred
     */
    @Override
    public void doDeleteUserClaimValue(String userName, String claimURI, String profileName) throws UserStoreException {

        System.out.println("Inside doDeleteUserClaimValue-------------------");
        Map<String, String> map = new HashMap<>();
        String attributeName;
        try {
            attributeName = getClaimAtrribute(claimURI, userName, null);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new UserStoreException("Error in obtaining claim mapping.", e);
        }
        map.put(attributeName, null);
        awsActions.updateObjectAttributes(directoryArn, getPayloadToUpdateObjectAttributes(AWSConstants.DELETE,
                facetNameOfUser, pathToUsers + "/" + userName, map));
        map.clear();
    }

    /**
     * delete user claim values of given user claims
     *
     * @param userName    of user
     * @param claims      to delete from user
     * @param profileName where claim belongs to
     * @throws UserStoreException if error occurred
     */
    @Override
    public void doDeleteUserClaimValues(String userName, String[] claims, String profileName) throws UserStoreException {

        System.out.println("Inside doDeleteUserClaimValues-------------------");
        for (String claimURI : claims) {
            doDeleteUserClaimValue(userName, claimURI, profileName);
        }
    }

    /**
     * get internal role names of given user
     *
     * @param userNames to filter the search
     * @return String[] of internal roles
     * @throws UserStoreException if any exception occurred
     */
    @Override
    protected String[] doGetDisplayNamesForInternalRole(String[] userNames) throws UserStoreException {

        throw new UserStoreException("doGetDisplayNamesForInternalRole not implemented for AWSUserStoreManager");
    }

    /**
     * Get profile names of user.
     *
     * @param userName to search.
     * @return String[] of profile names.
     * @throws UserStoreException if any exception occurred.
     */
    @Override
    public String[] getProfileNames(String userName) throws UserStoreException {

        return new String[]{UserCoreConstants.DEFAULT_PROFILE};
    }

    /**
     * Get properties of tenant.
     *
     * @param tenant to  search.
     * @return Map of properties.
     */
    @Override
    public Map<String, String> getProperties(Tenant tenant) {

        return this.realmConfig.getUserStoreProperties();
    }

    /**
     * Load default user store configration properties.
     *
     * @return Properties of default user store.
     */
    @Override
    public Properties getDefaultUserStoreProperties() {

        Properties properties = new Properties();
        properties.setMandatoryProperties(AWSUserStoreConstants.AWS_MANDATORY_UM_PROPERTIES.toArray
                (new Property[AWSUserStoreConstants.AWS_MANDATORY_UM_PROPERTIES.size()]));
        properties.setOptionalProperties(AWSUserStoreConstants.AWS_OPTIONAL_UM_PROPERTIES.toArray
                (new Property[AWSUserStoreConstants.AWS_OPTIONAL_UM_PROPERTIES.size()]));
        properties.setAdvancedProperties(AWSUserStoreConstants.AWS_ADVANCED_UM_PROPERTIES.toArray
                (new Property[AWSUserStoreConstants.AWS_ADVANCED_UM_PROPERTIES.size()]));

        return properties;
    }

    /**
     * Get all user properties belong to provided user profile.
     *
     * @param userName      username of user.
     * @param propertyNames names of properties to get.
     * @param profileName   profile name of user.
     * @return map object of properties.
     */
    @Override
    public Map<String, String> getUserPropertyValues(String userName, String[] propertyNames, String profileName)
            throws UserStoreException {

        System.out.println("Inside getUserPropertyValues-----------");
        Map<String, String> map = new HashMap<>();
        if (propertyNames == null) {
            if (log.isDebugEnabled()) {
                log.debug("No attributes requested");
            }
            return map;
        }
        if (log.isDebugEnabled()) {
            log.debug("Requesting attributes :" + Arrays.toString(propertyNames));
        }
        String[] propertyNamesSorted = propertyNames.clone();
        Arrays.sort(propertyNamesSorted);
        JSONObject objectAttributes = awsActions.listObjectAttributes(directoryArn, listObjectAttributesPayload(
                facetNameOfUser, pathToUsers + "/" + userName));
        JSONArray attributes = (JSONArray) objectAttributes.get(AWSConstants.ATTRIBUTES);
        for (Object attribute : attributes) {
            JSONObject keyVal = (JSONObject) attribute;
            String attributeName = ((JSONObject) keyVal.get(AWSConstants.KEY)).get(AWSConstants.NAME).toString();
            if (Arrays.binarySearch(propertyNamesSorted, attributeName) < 0) {
                continue;

            }
            map.put(attributeName, ((JSONObject) keyVal.get(AWSConstants.VALUE))
                    .get(AWSConstants.STRING_VALUE).toString());
        }

        return map;
    }

    /**
     * Create directory schema, create schema facets, publish schema, create directory, create (user, role,
     * user attribute) objects, create user to role association facet and create user to attribute association facet
     * if already not exists.
     *
     * @throws UserStoreException If error occurred.
     */
    private void setUpAWSDirectory() throws UserStoreException {
        System.out.println("Inside setUpAWSDirectory-------------------");
        pathToUsers = realmConfig.getUserStoreProperty(AWSConstants.PATH_TO_USERS);
        pathToRoles = realmConfig.getUserStoreProperty(AWSConstants.PATH_TO_ROLES);
        membershipType = realmConfig.getUserStoreProperty(AWSConstants.MEMBERSHIP_TYPE_OF_ROLES);
        directoryArn = realmConfig.getUserStoreProperty(AWSConstants.DIRECTORY_ARN);
        appliedSchemaArn = realmConfig.getUserStoreProperty(AWSConstants.SCHEMA_ARN);
        facetNameOfUser = realmConfig.getUserStoreProperty(AWSConstants.FACET_NAME_OF_USER);
        facetNameOfRole = realmConfig.getUserStoreProperty(AWSConstants.FACET_NAME_OF_ROLE);
        userNameAttribute = realmConfig.getUserStoreProperty(AWSConstants.USER_NAME_ATTRIBUTE);
        passwordAttribute = realmConfig.getUserStoreProperty(AWSConstants.PASSWORD_ATTRIBUTE);
        membershipAttribute = realmConfig.getUserStoreProperty(UserStoreConfigConstants.membershipAttribute);
        roleNameAttribute = realmConfig.getUserStoreProperty(AWSConstants.ROLE_NAME_ATTRIBUTE);
        memberOfAttribute = realmConfig.getUserStoreProperty(UserStoreConfigConstants.memberOfAttribute);
        passwordHashMethod = realmConfig.getUserStoreProperty(AWSRealmConstants.PASSWORD_HASH_METHOD);

        if(!checkDirectoryExist(directoryArn)) {
            throw new UserStoreException(String.format("Couldn't found any directory with DirectoryArn: %s in AWS.",
                    directoryArn));
        }

        //Create group facet.
        groupFacetName = AWSConstants.GROUP;
        Map<String, String> map = new HashMap<>();
        if (awsActions.getFacet(appliedSchemaArn, groupFacetName) == null) {
            map.put(AWSConstants.NAME, AWSConstants.REQUIRED_ALWAYS);
            awsActions.createSchemaFacet(appliedSchemaArn, buildPayloadToCreateSchemaFacet(groupFacetName, map));
            map.clear();
        }
        System.out.println("Schema is created ===========");

        Set<String> objectsPath = new LinkedHashSet<>();
        setObjectPaths(objectsPath, pathToUsers);
        setObjectPaths(objectsPath, pathToRoles);

        for (String path : objectsPath) {
            System.out.println("path ===========" + path);
        }
        for (String path : objectsPath) {
            int lastIndex = path.lastIndexOf("/");
            System.out.println("lastIndex---" + lastIndex);
            String parentPath;
            if (lastIndex == 0) {
                parentPath = "/";
                System.out.println("lastIndex is /" + parentPath);
            } else {
                parentPath = path.substring(0, lastIndex);
                System.out.println("lastIndex is 0" + parentPath);
            }
            String objectName = path.substring(lastIndex + 1);
            System.out.println(path + "------------" + parentPath + "---------" + objectName);
            JSONObject objectInfo = awsActions.getObjectInformation(directoryArn, path);
            System.out.println("objectInfo ----" + objectInfo);
            if (objectInfo == null) {
                map.put(AWSConstants.NAME, objectName);
                awsActions.createObject(directoryArn, getPayloadToCreateObject(objectName, groupFacetName,
                        parentPath, map));
                map.clear();
            }
        }
        typedLinkFacetName = AWSConstants.USER_ROLE_ASSOCIATION;
        if(membershipType.equals(AWSConstants.LINK)) {
            if (awsActions.getTypedLinkFacetInformation(appliedSchemaArn, typedLinkFacetName) == null) {
                List attributes = Arrays.asList(userNameAttribute, roleNameAttribute);
                awsActions.createTypedLinkFacet(appliedSchemaArn, getTypedLinkFacetPayload(typedLinkFacetName,
                        attributes));
            }
        }
    }

    /**
     *
     *
     * @param objectsPath Collection of objects path.
     * @param path Object path.
     */
    private void setObjectPaths(Set<String> objectsPath, String path) {
        int index = path.indexOf("/", 1);
        while (index >= 0) {
            objectsPath.add(path.substring(0, index));
            index = path.indexOf("/", index + 1);
        }
        objectsPath.add(path);
    }

    /**
     * Map the user to role list.
     *
     * @param userList The username of the user the roles need to be added to.
     * @param roleList The list of roles that needs to be mapped against the user.
     * @throws UserStoreException  If error occurred.
     */
    private void addUserToRoleList(String[] userList, String[] roleList) throws UserStoreException {

        System.out.println("Inside the process of adding user to role-------");
        Map<String, String> map = new HashMap<>();

        if (roleList != null && userList != null) {
            for (String userName : userList) {
                String sourceSelector = pathToUsers + "/" + userName;
                for (String role : roleList) {
                    String targetSelector = pathToRoles + "/" + role;
                    switch (membershipType) {
                        case AWSConstants.LINK:
                            map.put(userNameAttribute, userName);
                            map.put(roleNameAttribute, role);
                            awsActions.attachTypedLink(directoryArn, getAttachTypedLinkPayload(sourceSelector,
                                    targetSelector, typedLinkFacetName, map));
                            break;
                        case AWSConstants.ATTRIBUTE:
                            String users = userName;
                            String existingUsers = getValueOfAttribute(facetNameOfRole, targetSelector,
                                    memberOfAttribute);
                            if (StringUtils.isNotEmpty(existingUsers)) {
                                users += "," + existingUsers;
                            }
                            System.out.println("Users---" + users);
                            map.put(memberOfAttribute, users);
                            awsActions.updateObjectAttributes(directoryArn, getPayloadToUpdateObjectAttributes(
                                    AWSConstants.CREATE_OR_UPDATE, facetNameOfRole, targetSelector, map));
                            map.clear();
                            break;
                    }
                }

                if (membershipType.equals(AWSConstants.ATTRIBUTE)) {
                    String roles = String.join(",", roleList);
                    //get already existing role list the append this list then update the attribute
                    String existingRoles = getValueOfAttribute(facetNameOfUser, sourceSelector, membershipAttribute);
                    if (StringUtils.isNotEmpty(existingRoles)) {
                        roles = roles + "," + existingRoles;
                    }
                    System.out.println("roles list---"+roles);
                    map.put(membershipAttribute, roles);
                    awsActions.updateObjectAttributes(directoryArn, getPayloadToUpdateObjectAttributes(
                            AWSConstants.CREATE_OR_UPDATE, facetNameOfUser, sourceSelector, map));
                    map.clear();
                }
            }
        }
    }

    /**
     * Get attribute value for a particular attribute.
     *
     * @param facetName Name of the facet.
     * @param objectReference The reference that identifies the object in the directory structure.
     * @param attributeKey Attribute name for which the attribute value is needed.
     * @return Value of the attribute name.
     * @throws UserStoreException If error occurred.
     */
    private String getValueOfAttribute(String facetName, String objectReference, String attributeKey)
            throws UserStoreException {
        JSONObject objectAttributes = awsActions.listObjectAttributes(directoryArn,
                listObjectAttributesPayload(facetName, objectReference));
        JSONArray attributes = (JSONArray) objectAttributes.get(AWSConstants.ATTRIBUTES);
        String attributeValue = null;
        for (Object attribute : attributes) {
            JSONObject keyVal = (JSONObject) attribute;
            JSONObject key = (JSONObject) keyVal.get(AWSConstants.KEY);
            JSONObject value = (JSONObject) keyVal.get(AWSConstants.VALUE);
            if (attributeKey.equals(key.get(AWSConstants.NAME))) {
                attributeValue = value.get(AWSConstants.STRING_VALUE).toString();
                break;
            }
        }
        return attributeValue;
    }

    /**
     * Check whether the attribute name is already define in the facet or not.
     *
     * @param facetName Name of the facet.
     * @param attributeKey Attribute name
     * @return Boolean
     * @throws UserStoreException If error occurred.
     */
    private boolean isFacetAttributeExist (String facetName, String attributeKey) throws UserStoreException {
        String payload = "{\"MaxResults\": 100, \"Name\": \"" + facetName + "\"}";
        JSONObject objectAttributes = awsActions.listFacetAttributes(appliedSchemaArn, payload);
        JSONArray attributes = (JSONArray) objectAttributes.get(AWSConstants.ATTRIBUTES);
        for (Object attribute : attributes) {
            String key = ((JSONObject) attribute).get(AWSConstants.NAME).toString();
            if (attributeKey.equals(key)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check whether the directory is exist in AWS or not.
     * @param directoryArn The Amazon Resource Name (ARN).
     * @return Boolean
     * @throws UserStoreException If error occurred.
     */
    private boolean checkDirectoryExist(String directoryArn) throws UserStoreException {

        System.out.println("inside checkDirectoryExist");
        JSONObject directoryObjects = awsActions.listDirectories();
        JSONArray directories = (JSONArray) directoryObjects.get(AWSConstants.DIRECTORIES);
        for (Object directory : directories) {
            Object arn = ((JSONObject) directory).get(AWSConstants.DIRECTORY_ARN);
            if (arn.equals(directoryArn)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Generate payload to attach typed link.
     *
     * @param sourceSelector The reference that identifies the source object in the directory structure.
     * @param targetSelector The reference that identifies the target object in the directory structure.
     * @param facetName Name of the facet.
     * @param map List of properties to build the payload.
     * @return Payload.
     */
    private String getAttachTypedLinkPayload(String sourceSelector, String targetSelector, String facetName,
                                             Map<String, String> map) {
        StringBuilder builder = new StringBuilder();
        List<String> attributes = new LinkedList<>();
        for (Map.Entry<String, String> entry : map.entrySet()) {
            attributes.add("{\"AttributeName\": \"" + entry.getKey() + "\", \"Value\": {\"StringValue\": \""
                    + entry.getValue() + "\"}}");
        }
        builder.append("{\"Attributes\": [").append(String.join(",", attributes))
                .append("], \"SourceObjectReference\": {\"Selector\": \"").append(sourceSelector)
                .append("\"}, \"TargetObjectReference\": {\"Selector\": \"").append(targetSelector)
                .append("\"}, \"TypedLinkFacet\": {\"SchemaArn\": \"").append(appliedSchemaArn)
                .append("\", \"TypedLinkName\": \"").append(facetName).append("\"}}");
        return builder.toString();
    }

    /**
     * Generate payload to list object attributes.
     *
     * @param facetName Name of the facet.
     * @param objectReference The reference that identifies the object in the directory structure.
     * @return Payload.
     */
    private String listObjectAttributesPayload(String facetName, String objectReference){

        return "{\"FacetFilter\": { \"FacetName\": \"" + facetName + "\", \"SchemaArn\": \"" + appliedSchemaArn
                + "\"}, \"MaxResults\": 30, \"ObjectReference\": {\"Selector\": \""+ objectReference +"\"}}";
    }

    /**
     * Generate payload to get typed link.
     *
     * @param typedLinkName Name of the Typed Link.
     * @param objectReference The reference that identifies the object in the directory structure.
     * @return Payload.
     */
    private String getTypedLinkPayload (String typedLinkName, String objectReference) {
        StringBuilder builder = new StringBuilder();
        builder.append("{");
        if(typedLinkName != null){
            builder.append("\"FilterTypedLink\": {\"SchemaArn\": \"").append(appliedSchemaArn)
                    .append("\", \"TypedLinkName\": \"").append(typedLinkName).append("\"}, ");
        }
        builder.append("\"ObjectReference\": {\"Selector\": \"").append(objectReference).append("\"}}");
        return builder.toString();
    }

    /**
     * Generate payload to list incoming typedLinks.
     *
     * @param facetName Name of the Typed Link.
     * @param selector Path of the object in the directory structure.
     * @return Payload.
     */
    private String listIncomingTypedLinksPayload(String facetName, String selector){
        StringBuilder builder = new StringBuilder();
        builder.append("{");
        if (StringUtils.isNotEmpty(facetName)) {
            builder.append("\"FilterTypedLink\": {\"SchemaArn\": \"")
                    .append(appliedSchemaArn).append("\", \"TypedLinkName\": \"").append(facetName).append("\"}, ");
        }
        builder.append("\"ObjectReference\": {\"Selector\": \"").append(selector).append("\"}}");
        return builder.toString();
    }

    /**
     * Generate payload to update facet.
     *
     * @param facetName Name of the facet.
     * @param attributeList Attribute list.
     * @return Payload.
     */
    private String getPayloadToupdateFacet(String facetName, List<String> attributeList) {
        StringBuilder builder = new StringBuilder();
        List<String> attributes = new LinkedList<>();
        for (String attributeName : attributeList) {
            attributes.add("{\"Action\": \"CREATE_OR_UPDATE\", \"Attribute\": { \"AttributeDefinition\": {\"Type\": " +
                    "\"STRING\"}, \"Name\": \"" + attributeName + "\", \"RequiredBehavior\": \"NOT_REQUIRED\"}}");
        }
        return builder.append("{\"AttributeUpdates\": [").append(String.join(",", attributes)).append("], \"Name\": \"")
                .append(facetName).append("\"}").toString();
    }

    /**
     * Generate payload to update objectAttributes.
     *
     * @param action The action to perform when updating the attribute.
     * @param facetName Name of the facet.
     * @param objectReference The reference that identifies the object in the directory structure.
     * @param map List of properties to build the payload.
     * @return Payload.
     */
    private String getPayloadToUpdateObjectAttributes(String action, String facetName, String objectReference,
                                                      Map<String, String> map) {
        StringBuilder builder = new StringBuilder();
        List<String> attributes = new LinkedList<>();
        for (Map.Entry<String, String> entry : map.entrySet()) {
            attributes.add("{\"ObjectAttributeAction\": {\"ObjectAttributeActionType\": \"" + action + "\", " +
                    "\"ObjectAttributeUpdateValue\": {\"StringValue\": \"" + entry.getValue() + "\"}}, " +
                    "\"ObjectAttributeKey\": {\"FacetName\": \"" + facetName + "\", \"Name\": \"" + entry.getKey()
                    + "\", \"SchemaArn\": \"" + appliedSchemaArn + "\"}}");
        }
        return builder.append("{\"AttributeUpdates\": [").append(String.join(",", attributes))
                .append("], \"ObjectReference\": {\"Selector\": \"").append(objectReference).append("\"}}").toString();
    }

    /**
     * Generate payload to create object.
     *
     * @param linkName        Name of the link.
     * @param facetName       Name of the facet.
     * @param parentReference The parent reference to which this object will be attached.
     * @param map             List of properties to build the payload.
     * @return Payload.
     */
    private String getPayloadToCreateObject(String linkName, String facetName, String parentReference,
                                            Map<String, String> map) {
        StringBuilder builder = new StringBuilder();
        List<String> attributes = new LinkedList<>();
        for (Map.Entry<String, String> entry : map.entrySet()) {
            attributes.add("{\"Key\": {\"FacetName\": \"" + facetName + "\", \"Name\": \"" + entry.getKey() + "\", " +
                    "\"SchemaArn\": \"" + appliedSchemaArn + "\"}, \"Value\": {\"StringValue\": \"" + entry.getValue()
                    + "\"}}");
        }
        return builder.append("{\"LinkName\": \"").append(linkName).append("\", \"ObjectAttributeList\": [")
                .append(String.join(",", attributes)).append("], \"ParentReference\": {\"Selector\": \"")
                .append(parentReference).append("\"}, \"SchemaFacets\": [{\"FacetName\" : \"").append(facetName)
                .append("\", \"SchemaArn\": \"").append(appliedSchemaArn).append("\"}]}").toString();
    }

    /**
     * Generate payload to get typedLink facet.
     *
     * @param facetName  Name of the facet.
     * @param attributes List of attributes to build the payload.
     * @return Payload.
     */
    private String getTypedLinkFacetPayload(String facetName, List attributes) {
        StringBuilder builder = new StringBuilder();
        List<String> attribute = new LinkedList<>();
        List<String> attributeOrder = new LinkedList<>();
        for (Object key : attributes) {
            attribute.add("{\"Name\":\"" + key + "\",\"RequiredBehavior\": \"REQUIRED_ALWAYS\", \"Type\": \"STRING\"}");
            attributeOrder.add("\"" + key + "\"");
        }
        return builder.append("{\"Facet\": {\"Attributes\": [").append(String.join(",", attribute))
                .append("], \"IdentityAttributeOrder\": [").append(String.join(",", attributeOrder))
                .append("], \"Name\": \"").append(facetName).append("\"}}").toString();
    }

    /**
     * Generate payload to detach object.
     *
     * @param linkName        Name of the link.
     * @param parentReference The parent reference to which this object will be attached.
     * @return Payload.
     */
    private String getPayloadTodetachObject(String linkName, String parentReference) {

        return "{\"LinkName\": \"" + linkName + "\", \"ParentReference\": {\"Selector\": \"" + parentReference + "\"}}";
    }

    /**
     * Generate payload to create schema facet.
     *
     * @param facetName Name of the facet.
     * @param map       List of properties to build the payload.
     * @return Payload.
     */
    private String buildPayloadToCreateSchemaFacet(String facetName, Map<String, String> map) {
        StringBuilder builder = new StringBuilder();
        boolean isImmutable = false;
        if (StringUtils.equals(facetName, AWSConstants.GROUP)) {
            isImmutable = true;
        }
        List<String> attributes = new LinkedList<>();
        for (Map.Entry<String, String> entry : map.entrySet()) {
            attributes.add("{\"AttributeDefinition\": {\"IsImmutable\": " + isImmutable + ", \"Type\": \"STRING\"}, " +
                    "\"Name\": \"" + entry.getKey() + "\", \"RequiredBehavior\": \"" + entry.getValue() + "\"}");
        }
        return builder.append("{\"Attributes\": [").append(String.join(",", attributes)).append("], \"Name\": \"")
                .append(facetName).append("\", \"ObjectType\": \"NODE\"}").toString();
    }
}
