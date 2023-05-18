/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.api.server.jwt.issuers.v1.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.util.ArrayList;
import java.util.List;
import org.wso2.carbon.identity.api.server.jwt.issuers.v1.model.FederatedAuthenticatorListItem;
import javax.validation.constraints.*;


import io.swagger.annotations.*;
import java.util.Objects;
import javax.validation.Valid;
import javax.xml.bind.annotation.*;

public class FederatedAuthenticatorListResponse  {
  
    private String defaultAuthenticatorId;
    private List<FederatedAuthenticatorListItem> authenticators = null;


    /**
    **/
    public FederatedAuthenticatorListResponse defaultAuthenticatorId(String defaultAuthenticatorId) {

        this.defaultAuthenticatorId = defaultAuthenticatorId;
        return this;
    }
    
    @ApiModelProperty(example = "U0FNTDJBdXRoZW50aWNhdG9y", value = "")
    @JsonProperty("defaultAuthenticatorId")
    @Valid
    public String getDefaultAuthenticatorId() {
        return defaultAuthenticatorId;
    }
    public void setDefaultAuthenticatorId(String defaultAuthenticatorId) {
        this.defaultAuthenticatorId = defaultAuthenticatorId;
    }

    /**
    **/
    public FederatedAuthenticatorListResponse authenticators(List<FederatedAuthenticatorListItem> authenticators) {

        this.authenticators = authenticators;
        return this;
    }
    
    @ApiModelProperty(value = "")
    @JsonProperty("authenticators")
    @Valid
    public List<FederatedAuthenticatorListItem> getAuthenticators() {
        return authenticators;
    }
    public void setAuthenticators(List<FederatedAuthenticatorListItem> authenticators) {
        this.authenticators = authenticators;
    }

    public FederatedAuthenticatorListResponse addAuthenticatorsItem(FederatedAuthenticatorListItem authenticatorsItem) {
        if (this.authenticators == null) {
            this.authenticators = new ArrayList<>();
        }
        this.authenticators.add(authenticatorsItem);
        return this;
    }

    

    @Override
    public boolean equals(java.lang.Object o) {

        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        FederatedAuthenticatorListResponse federatedAuthenticatorListResponse = (FederatedAuthenticatorListResponse) o;
        return Objects.equals(this.defaultAuthenticatorId, federatedAuthenticatorListResponse.defaultAuthenticatorId) &&
            Objects.equals(this.authenticators, federatedAuthenticatorListResponse.authenticators);
    }

    @Override
    public int hashCode() {
        return Objects.hash(defaultAuthenticatorId, authenticators);
    }

    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();
        sb.append("class FederatedAuthenticatorListResponse {\n");
        
        sb.append("    defaultAuthenticatorId: ").append(toIndentedString(defaultAuthenticatorId)).append("\n");
        sb.append("    authenticators: ").append(toIndentedString(authenticators)).append("\n");
        sb.append("}");
        return sb.toString();
    }

    /**
    * Convert the given object to string with each line indented by 4 spaces
    * (except the first line).
    */
    private String toIndentedString(java.lang.Object o) {

        if (o == null) {
            return "null";
        }
        return o.toString().replace("\n", "\n");
    }
}

