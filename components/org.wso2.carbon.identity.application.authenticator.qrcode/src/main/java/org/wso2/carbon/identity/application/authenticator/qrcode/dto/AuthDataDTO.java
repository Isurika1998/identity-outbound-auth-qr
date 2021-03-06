/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 *
 */

package org.wso2.carbon.identity.application.authenticator.qrcode.dto;

import java.io.Serializable;

/**
 * DTO class for holding authentication data.
 */
public class AuthDataDTO implements Serializable {

    private static final long serialVersionUID = 5355319579322887235L;
    private String tenantDomain;
    private String clientID;

    public void setTenantDomain(String tenantDomain) {

        this.tenantDomain = tenantDomain;
    }

    public String getTenantDomain() {

        return this.tenantDomain;
    }

    public void setClientID(String clientID) {

        this.clientID = clientID;
    }

    public String getClientID() {

        return this.clientID;
    }
}
