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
 * Model for error codes.
 **/
@ApiModel(description = "Model for error codes")
public class ErrorDTO  {
  
    private String code;
    private String message;
    private String description;
    private String traceId;

    /**
    **/
    public ErrorDTO code(String code) {

        this.code = code;
        return this;
    }
    
    @ApiModelProperty(example = "PDM-15001", value = "")
    @JsonProperty("code")
    @Valid
    public String getCode() {
        return code;
    }
    public void setCode(String code) {
        this.code = code;
    }

    /**
    **/
    public ErrorDTO message(String message) {

        this.message = message;
        return this;
    }
    
    @ApiModelProperty(example = "An error occurred...", value = "")
    @JsonProperty("message")
    @Valid
    public String getMessage() {
        return message;
    }
    public void setMessage(String message) {
        this.message = message;
    }

    /**
    **/
    public ErrorDTO description(String description) {

        this.description = description;
        return this;
    }
    
    @ApiModelProperty(example = "The error occurred due to...", value = "")
    @JsonProperty("description")
    @Valid
    public String getDescription() {
        return description;
    }
    public void setDescription(String description) {
        this.description = description;
    }

    /**
    **/
    public ErrorDTO traceId(String traceId) {

        this.traceId = traceId;
        return this;
    }
    
    @ApiModelProperty(example = "b03f90c9-6723-48f6-863b-a35f1ac77f57", value = "")
    @JsonProperty("traceId")
    @Valid
    public String getTraceId() {
        return traceId;
    }
    public void setTraceId(String traceId) {
        this.traceId = traceId;
    }



    @Override
    public boolean equals(java.lang.Object o) {

        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        ErrorDTO errorDTO = (ErrorDTO) o;
        return Objects.equals(this.code, errorDTO.code) &&
            Objects.equals(this.message, errorDTO.message) &&
            Objects.equals(this.description, errorDTO.description) &&
            Objects.equals(this.traceId, errorDTO.traceId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(code, message, description, traceId);
    }

    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();
        sb.append("class ErrorDTO {\n");
        
        sb.append("    code: ").append(toIndentedString(code)).append("\n");
        sb.append("    message: ").append(toIndentedString(message)).append("\n");
        sb.append("    description: ").append(toIndentedString(description)).append("\n");
        sb.append("    traceId: ").append(toIndentedString(traceId)).append("\n");
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
