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

package org.wso2.carbon.identity.api.user.qrcode.device.handler.v1.impl;

import org.wso2.carbon.identity.api.user.qrcode.device.handler.v1.MeApiService;
import org.wso2.carbon.identity.api.user.qrcode.device.handler.v1.model.RegistrationRequestDTO;
import javax.ws.rs.core.Response;

/**
 * MeApiServiceImpl.
 */
public class MeApiServiceImpl implements MeApiService {

    @Override
    public Response meQrAuthDevicesDeviceIdDelete(String deviceId) {

        // do some magic!
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response meQrAuthDevicesDeviceIdGet(String deviceId) {

        // do some magic!
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response meQrAuthDevicesGet() {

        // do some magic!
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response meQrAuthDevicesPost(RegistrationRequestDTO registrationRequestDTO) {

        // do some magic!
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response meQrAuthDiscoveryDataGet() {

        // do some magic!
        return Response.ok().entity("magic!").build();
    }
}
