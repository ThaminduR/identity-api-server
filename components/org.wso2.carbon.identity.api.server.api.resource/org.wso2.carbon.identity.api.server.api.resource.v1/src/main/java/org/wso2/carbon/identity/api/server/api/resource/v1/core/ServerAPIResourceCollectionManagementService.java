/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.api.server.api.resource.v1.core;

import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.api.resource.collection.mgt.constant.APIResourceCollectionManagementConstants;
import org.wso2.carbon.identity.api.resource.collection.mgt.exception.APIResourceCollectionMgtException;
import org.wso2.carbon.identity.api.resource.collection.mgt.model.APIResourceCollection;
import org.wso2.carbon.identity.api.resource.collection.mgt.model.APIResourceCollectionSearchResult;
import org.wso2.carbon.identity.api.server.api.resource.common.APIResourceManagementServiceHolder;
import org.wso2.carbon.identity.api.server.api.resource.v1.APIResourceCollectionItem;
import org.wso2.carbon.identity.api.server.api.resource.v1.APIResourceCollectionListItem;
import org.wso2.carbon.identity.api.server.api.resource.v1.APIResourceCollectionListResponse;
import org.wso2.carbon.identity.api.server.api.resource.v1.APIResourceCollectionResponse;
import org.wso2.carbon.identity.api.server.api.resource.v1.APIResourceCollectionResponseApiResources;
import org.wso2.carbon.identity.api.server.api.resource.v1.ScopeGetModel;
import org.wso2.carbon.identity.api.server.api.resource.v1.constants.APIResourceMgtEndpointConstants;
import org.wso2.carbon.identity.api.server.api.resource.v1.util.APIResourceMgtEndpointUtil;
import org.wso2.carbon.identity.application.common.model.APIResource;
import org.wso2.carbon.identity.application.common.model.Scope;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import javax.ws.rs.core.Response;

import static org.wso2.carbon.identity.api.server.common.Constants.V1_API_PATH_COMPONENT;

/**
 * Server API Resource Collection Management Service.
 */
public class ServerAPIResourceCollectionManagementService {

    /**
     * Get API Resource Collections List.
     *
     * @param filter filter string.
     * @return API Resource Collections List.
     */
    public APIResourceCollectionListResponse getAPIResourceCollections(String filter) {

        APIResourceCollectionListResponse apiResourceCollectionListResponse = new APIResourceCollectionListResponse();

        try {
            APIResourceCollectionSearchResult apiResourceCollectionSearchResult = APIResourceManagementServiceHolder
                    .getApiResourceCollectionManager().getAPIResourceCollections(filter);

            List<APIResourceCollection> apiResourceCollections = apiResourceCollectionSearchResult
                    .getAPIResourceCollections();
            if (apiResourceCollections == null || apiResourceCollections.isEmpty()) {
                apiResourceCollectionListResponse.setTotalResults(0);
                apiResourceCollectionListResponse.setApiResourceCollections(new ArrayList<>());
                return apiResourceCollectionListResponse;
            }
            apiResourceCollectionListResponse.setTotalResults(apiResourceCollectionSearchResult.getTotalCount());
            apiResourceCollectionListResponse.setApiResourceCollections(
                    apiResourceCollections.stream().map(this::buildAPIResourceCollectionListItem)
                            .collect(Collectors.toList()));
        } catch (APIResourceCollectionMgtException e) {
            throw APIResourceMgtEndpointUtil.handleAPIResourceCollectionMgtException(e);
        }
        return apiResourceCollectionListResponse;
    }

    /**
     * Get API Resource Collection by collection id.
     *
     * @param collectionId API Resource Collection id.
     * @return API Resource Collection.
     */
    public APIResourceCollectionResponse getAPIResourceCollectionByCollectionId(String collectionId) {

        APIResourceCollectionResponse apiResourceCollectionResponse = new APIResourceCollectionResponse();

        try {
            APIResourceCollection apiResourceCollection = APIResourceManagementServiceHolder
                    .getApiResourceCollectionManager().getAPIResourceCollectionById(collectionId,
                            CarbonContext.getThreadLocalCarbonContext().getTenantDomain());
            if (apiResourceCollection == null) {
                throw APIResourceMgtEndpointUtil.handleException(Response.Status.NOT_FOUND,
                        APIResourceMgtEndpointConstants.ErrorMessage.ERROR_CODE_API_RESOURCE_COLLECTION_NOT_FOUND,
                        collectionId);
            }
            apiResourceCollectionResponse.setId(apiResourceCollection.getId());
            apiResourceCollectionResponse.setName(apiResourceCollection.getName());
            apiResourceCollectionResponse.setDisplayName(apiResourceCollection.getDisplayName());
            apiResourceCollectionResponse.setType(apiResourceCollection.getType());

            List<APIResourceCollectionItem> readAPIResourceCollectionItems = getAPIResourceCollectionItems(
                    apiResourceCollection, APIResourceCollectionManagementConstants.READ);
            List<APIResourceCollectionItem> writeAPIResourceCollectionItems = getAPIResourceCollectionItems(
                    apiResourceCollection, APIResourceCollectionManagementConstants.WRITE);

            APIResourceCollectionResponseApiResources apiResourceCollectionResponseApiResources =
                    new APIResourceCollectionResponseApiResources();
            apiResourceCollectionResponseApiResources.setRead(readAPIResourceCollectionItems);
            apiResourceCollectionResponseApiResources.setWrite(writeAPIResourceCollectionItems);
            apiResourceCollectionResponse.setApiResources(apiResourceCollectionResponseApiResources);
        } catch (APIResourceCollectionMgtException e) {
            throw APIResourceMgtEndpointUtil.handleAPIResourceCollectionMgtException(e);
        }
        return apiResourceCollectionResponse;
    }

    /**
     * Build API Resource Collection List Item from API Resource Collection.
     *
     * @param apiResourceCollection API Resource Collection.
     * @return API Resource Collection List Item.
     */
    private APIResourceCollectionListItem buildAPIResourceCollectionListItem(
            APIResourceCollection apiResourceCollection) {

        return new APIResourceCollectionListItem()
                .id(apiResourceCollection.getId())
                .name(apiResourceCollection.getName())
                .displayName(apiResourceCollection.getDisplayName())
                .type(apiResourceCollection.getType())
                .self(V1_API_PATH_COMPONENT + APIResourceMgtEndpointConstants.API_RESOURCE_COLLECTION_PATH_COMPONENT +
                        "/" + apiResourceCollection.getId());
    }

    /**
     * Build ScopeGetModel from Scope.
     *
     * @param scope Scope object.
     * @return ScopeGetModel object.
     */
    private ScopeGetModel buildScopeGetResponse(Scope scope) {

        return new ScopeGetModel()
                .id(scope.getId())
                .name(scope.getName())
                .displayName(scope.getDisplayName())
                .description(scope.getDescription());
    }

    /**
     * Get API Resource Collection Items.
     *
     * @param apiResourceCollection API Resource Collection.
     * @param resourceType          Resource type.
     * @return API Resource Collection Items.
     */
    private List<APIResourceCollectionItem> getAPIResourceCollectionItems(APIResourceCollection apiResourceCollection,
                                                                          String resourceType) {

        if (apiResourceCollection.getApiResources() == null || apiResourceCollection.getApiResources()
                .get(resourceType) == null) {
            return Collections.emptyList();
        }
        return apiResourceCollection.getApiResources().get(resourceType).stream()
                .map(this::buildAPIResourceCollectionItem).collect(Collectors.toList());
    }

    /**
     * Build API Resource List Item from API Resource.
     *
     * @param apiResource API Resource.
     * @return API Resource List Item.
     */
    private APIResourceCollectionItem buildAPIResourceCollectionItem(APIResource apiResource) {

        List<ScopeGetModel> scopesList = (apiResource.getScopes() != null)
                ? apiResource.getScopes().stream().map(this::buildScopeGetResponse).collect(Collectors.toList())
                : Collections.emptyList();

        return new APIResourceCollectionItem()
                .id(apiResource.getId())
                .name(apiResource.getName())
                .description(apiResource.getDescription())
                .type(apiResource.getType())
                .scopes(scopesList)
                .self(V1_API_PATH_COMPONENT + APIResourceMgtEndpointConstants.API_RESOURCE_PATH_COMPONENT
                        + "/" + apiResource.getId());
    }
}
