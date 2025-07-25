/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.api.server.flow.management.v1.response.handlers;

import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.api.server.flow.management.common.FlowMgtServiceHolder;
import org.wso2.carbon.identity.api.server.flow.management.v1.ExecutorConnections;
import org.wso2.carbon.identity.api.server.flow.management.v1.FlowMetaResponse;
import org.wso2.carbon.identity.api.server.flow.management.v1.constants.FlowEndpointConstants;
import org.wso2.carbon.identity.api.server.flow.management.v1.utils.Utils;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.flow.mgt.exception.FlowMgtClientException;
import org.wso2.carbon.identity.multi.attribute.login.constants.MultiAttributeLoginConstants;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.idp.mgt.model.IdpSearchResult;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.api.server.flow.management.v1.constants.FlowEndpointConstants.ErrorMessages.ERROR_CODE_GET_IDENTITY_PROVIDERS;
import static org.wso2.carbon.identity.api.server.flow.management.v1.constants.FlowEndpointConstants.Executors.APPLE_EXECUTOR;
import static org.wso2.carbon.identity.api.server.flow.management.v1.constants.FlowEndpointConstants.Executors.EMAIL_OTP_EXECUTOR;
import static org.wso2.carbon.identity.api.server.flow.management.v1.constants.FlowEndpointConstants.Executors.FACEBOOK_EXECUTOR;
import static org.wso2.carbon.identity.api.server.flow.management.v1.constants.FlowEndpointConstants.Executors.GITHUB_EXECUTOR;
import static org.wso2.carbon.identity.api.server.flow.management.v1.constants.FlowEndpointConstants.Executors.GOOGLE_EXECUTOR;
import static org.wso2.carbon.identity.api.server.flow.management.v1.constants.FlowEndpointConstants.Executors.MAGIC_LINK_EXECUTOR;
import static org.wso2.carbon.identity.api.server.flow.management.v1.constants.FlowEndpointConstants.Executors.OFFICE365_EXECUTOR;
import static org.wso2.carbon.identity.api.server.flow.management.v1.constants.FlowEndpointConstants.Executors.OPENID_CONNECT_EXECUTOR;
import static org.wso2.carbon.identity.api.server.flow.management.v1.constants.FlowEndpointConstants.Executors.PASSWORD_ONBOARD_EXECUTOR;
import static org.wso2.carbon.identity.api.server.flow.management.v1.constants.FlowEndpointConstants.Executors.PASSWORD_PROVISIONING_EXECUTOR;
import static org.wso2.carbon.identity.api.server.flow.management.v1.constants.FlowEndpointConstants.Executors.SMS_OTP_EXECUTOR;
import static org.wso2.carbon.identity.api.server.flow.management.v1.constants.FlowEndpointConstants.IDP_TEMPLATE_ID;
import static org.wso2.carbon.identity.api.server.flow.management.v1.constants.FlowEndpointConstants.MICROSOFT_IDP_TEMPLATE_ID;

/**
 * Abstract class for handling meta responses for different flows.
 * This class provides methods to retrieve flow type, attribute profile,
 * supported executors, connector configurations, and connection meta information.
 */
public abstract class AbstractMetaResponseHandler {

    private static final String MULTI_ATTRIBUTE_LOGIN_ENABLED = "multiAttributeLoginEnabled";

    /**
     * Get the flow type.
     *
     * @return Flow type.
     */
    public abstract String getFlowType();

    /**
     * Get the attribute profile.
     *
     * @return Attribute profile.
     */
    public abstract String getAttributeProfile();

    /**
     * Get the supported executors for the flow.
     *
     * @return List of supported executors.
     */
    public List<String> getSupportedExecutors() {

        ArrayList<String> supportedExecutors = new ArrayList<>();
        supportedExecutors.add(PASSWORD_PROVISIONING_EXECUTOR);
        supportedExecutors.add(PASSWORD_ONBOARD_EXECUTOR);
        supportedExecutors.add(EMAIL_OTP_EXECUTOR);
        supportedExecutors.add(SMS_OTP_EXECUTOR);
        supportedExecutors.add(MAGIC_LINK_EXECUTOR);
        return supportedExecutors;
    }

    /**
     * Get the connector configurations for the flow.
     *
     * @return Connector configurations.
     */
    public Map<String, Boolean> getConnectorConfigs() {

        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        Map<String, Boolean> connectorConfigs = new HashMap<>();
        connectorConfigs.put(MULTI_ATTRIBUTE_LOGIN_ENABLED,
                Utils.getGovernanceConfig(tenantDomain, MultiAttributeLoginConstants.MULTI_ATTRIBUTE_LOGIN_PROPERTY));
        return connectorConfigs;
    }

    /**
     * Get the required input fields for the flow.
     *
     * @return List of required input fields.
     */
    public abstract List<String> getRequiredInputFields();

    /**
     * Create the meta response object populated with common values.
     *
     * @return FlowMetaResponse instance.
     */
    public FlowMetaResponse createResponse() {

        FlowMetaResponse response = new FlowMetaResponse();
        response.setFlowType(getFlowType());
        response.setAttributeProfile(getAttributeProfile());
        response.setSupportedExecutors(getSupportedExecutors());
        response.setConnectorConfigs(getConnectorConfigs());
        response.setExecutorConnections(getExecutorConnections());
        return response;
    }

    /**
     * Return login related input fields common across flows.
     */
    protected List<String> getLoginInputFields() {

        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        List<String> fields = new java.util.ArrayList<>();
        if (Utils.getGovernanceConfig(tenantDomain, MultiAttributeLoginConstants.MULTI_ATTRIBUTE_LOGIN_PROPERTY)) {
            fields.add(FlowEndpointConstants.USER_IDENTIFIER);
            fields.add(FlowEndpointConstants.USERNAME_IDENTIFIER);
        } else {
            fields.add(FlowEndpointConstants.USERNAME_IDENTIFIER);
        }
        return fields;
    }

    protected List<ExecutorConnections> getExecutorConnections() {

        try {

            Map<String, String> connectionExecutorMap = getConnectionExecutorMap();
            Map<String, ExecutorConnections> executorConnections = new HashMap<>();
            getSupportedExecutors().forEach(executorName -> {
                if (connectionExecutorMap.containsValue(executorName)) {
                    ExecutorConnections executorConnectionsObj = new ExecutorConnections()
                            .executorName(executorName)
                            .connections(new ArrayList<>());
                    executorConnections.put(executorName, executorConnectionsObj);
                }
            });

            List<IdentityProvider> identityProviders = getAllIdPs();
            for (IdentityProvider identityProvider : identityProviders) {
                if (identityProvider.getDefaultAuthenticatorConfig() != null &&
                        identityProvider.getDefaultAuthenticatorConfig().getName() != null) {

                    // Handle the case for Microsoft Identity Provider separately since it uses OIDC authenticator.
                    // This is a workaround to avoid the Microsoft Identity Provider being added to the OpenID Connect
                    // executor connections.
                    boolean isMicrosoftIdP = Arrays.stream(identityProvider.getIdpProperties())
                            .anyMatch(property ->
                                    IDP_TEMPLATE_ID.equals(property.getName()) &&
                                            MICROSOFT_IDP_TEMPLATE_ID.equals(property.getValue()));
                    if (isMicrosoftIdP && executorConnections.containsKey(OFFICE365_EXECUTOR)) {
                        executorConnections.get(OFFICE365_EXECUTOR)
                                .addConnectionsItem(identityProvider.getIdentityProviderName());
                        continue;
                    }

                    String authenticatorName = identityProvider.getDefaultAuthenticatorConfig().getName();
                    if (connectionExecutorMap.containsKey(authenticatorName) &&
                            executorConnections.containsKey(connectionExecutorMap.get(authenticatorName))) {
                        executorConnections.get(connectionExecutorMap.get(authenticatorName))
                                .addConnectionsItem(identityProvider.getIdentityProviderName());
                    }
                }
            }
            return new ArrayList<>(executorConnections.values());
        } catch (IdentityProviderManagementException e) {
            throw Utils.handleFlowMgtException(new FlowMgtClientException(
                    ERROR_CODE_GET_IDENTITY_PROVIDERS.getCode(),
                    ERROR_CODE_GET_IDENTITY_PROVIDERS.getMessage(),
                    ERROR_CODE_GET_IDENTITY_PROVIDERS.getDescription(), e));
        }
    }

    private static Map<String, String> getConnectionExecutorMap() {

        Map<String, String> connectionExecutorMap = new HashMap<>();
        connectionExecutorMap.put(FlowEndpointConstants.Authenticators.GOOGLE_AUTHENTICATOR, GOOGLE_EXECUTOR);
        connectionExecutorMap.put(FlowEndpointConstants.Authenticators.FACEBOOK_AUTHENTICATOR, FACEBOOK_EXECUTOR);
        connectionExecutorMap.put(FlowEndpointConstants.Authenticators.GITHUB_AUTHENTICATOR, GITHUB_EXECUTOR);
        connectionExecutorMap.put(FlowEndpointConstants.Authenticators.OFFICE365_AUTHENTICATOR, OFFICE365_EXECUTOR);
        connectionExecutorMap.put(FlowEndpointConstants.Authenticators.APPLE_AUTHENTICATOR, APPLE_EXECUTOR);
        connectionExecutorMap.put(FlowEndpointConstants.Authenticators.OPENID_CONNECT_AUTHENTICATOR,
                OPENID_CONNECT_EXECUTOR);
        return connectionExecutorMap;
    }

    private static List<IdentityProvider> getAllIdPs() throws IdentityProviderManagementException {

        List<IdentityProvider> identityProviders = new ArrayList<>();
        IdpManager idpManager = FlowMgtServiceHolder.getIdpManager();
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        List<String> requiredAttributes = Collections.singletonList("federatedAuthenticators");

        int offset = 0;
        int totalCount;
        int pageSize = 100;
        do {
            IdpSearchResult idpSearchResult = idpManager.getIdPs(pageSize, offset, null, null, null,
                    tenantDomain, requiredAttributes);
            if (idpSearchResult != null && idpSearchResult.getIdPs() != null) {
                identityProviders.addAll(idpSearchResult.getIdPs());
            }
            totalCount = idpSearchResult != null ? idpSearchResult.getTotalIDPCount() : 0;
            offset += pageSize;
        } while (offset < totalCount);
        return identityProviders;
    }
}
