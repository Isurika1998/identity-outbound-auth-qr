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

package org.wso2.carbon.identity.api.user.qrcode.handler.v1.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.util.Objects;
import javax.validation.Valid;

/**
 * User authentication information.
 **/
@ApiModel(description = "User authentication information")
public class AuthDataDTO  {
  
    private String sessionDataKey;
    private String tenantDomain;
    private String clientID;

    /**
    * SessionDataKey.
    **/
    public AuthDataDTO sessionDataKey(String sessionDataKey) {

        this.sessionDataKey = sessionDataKey;
        return this;
    }
    
    @ApiModelProperty(example = "b03f90c9-6723-48f6-863b-a35f1ac77f57", value = "SessionDataKey")
    @JsonProperty("sessionDataKey")
    @Valid
    public String getSessionDataKey() {
        return sessionDataKey;
    }
    public void setSessionDataKey(String sessionDataKey) {
        this.sessionDataKey = sessionDataKey;
    }

    /**
    * Tenant domain.
    **/
    public AuthDataDTO tenantDomain(String tenantDomain) {

        this.tenantDomain = tenantDomain;
        return this;
    }
    
    @ApiModelProperty(example = "photogallery.com", value = "Tenant domain")
    @JsonProperty("tenantDomain")
    @Valid
    public String getTenantDomain() {
        return tenantDomain;
    }
    public void setTenantDomain(String tenantDomain) {
        this.tenantDomain = tenantDomain;
    }

    /**
    * Client ID.
    **/
    public AuthDataDTO clientID(String clientID) {

        this.clientID = clientID;
        return this;
    }
    
    @ApiModelProperty(example = "A9qHTjNwUOAifHqCdfcvwLYfslYa", value = "Client ID")
    @JsonProperty("clientID")
    @Valid
    public String getClientID() {
        return clientID;
    }
    public void setClientID(String clientID) {
        this.clientID = clientID;
    }



    @Override
    public boolean equals(java.lang.Object o) {

        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        AuthDataDTO authDataDTO = (AuthDataDTO) o;
        return Objects.equals(this.sessionDataKey, authDataDTO.sessionDataKey) &&
            Objects.equals(this.tenantDomain, authDataDTO.tenantDomain) &&
            Objects.equals(this.clientID, authDataDTO.clientID);
    }

    @Override
    public int hashCode() {
        return Objects.hash(sessionDataKey, tenantDomain, clientID);
    }

    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();
        sb.append("class AuthDataDTO {\n");
        
        sb.append("    sessionDataKey: ").append(toIndentedString(sessionDataKey)).append("\n");
        sb.append("    tenantDomain: ").append(toIndentedString(tenantDomain)).append("\n");
        sb.append("    clientID: ").append(toIndentedString(clientID)).append("\n");
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

