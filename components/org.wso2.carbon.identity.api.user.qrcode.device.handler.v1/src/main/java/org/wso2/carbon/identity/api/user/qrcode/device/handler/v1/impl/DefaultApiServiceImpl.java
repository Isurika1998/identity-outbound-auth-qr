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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.wso2.carbon.identity.api.user.qrcode.device.handler.v1.DefaultApiService;
import org.wso2.carbon.identity.api.user.qrcode.device.handler.v1.core.QRDeviceHandlerService;

import javax.ws.rs.core.Response;

/**
 * Implementation class of QR device Handler Admin APIs .
 */
public class DefaultApiServiceImpl implements DefaultApiService {

    private static final Log log = LogFactory.getLog(DefaultApiServiceImpl.class);

    @Autowired
    private QRDeviceHandlerService deviceHandlerService;

    @Override
    public Response userIdQrAuthDevicesDeviceIdDelete(String userId, String deviceId) {

        if (log.isDebugEnabled()) {
            log.debug("Removing device : " + deviceId + " of User : " + userId + ".");
        }
        deviceHandlerService.unregisterDevice(deviceId);
        return Response.noContent().build();
    }

    @Override
    public Response userIdQrAuthDevicesDeviceIdGet(String userId, String deviceId) {

        if (log.isDebugEnabled()) {
            log.debug("Fetching data of device : " + deviceId + " of user : " + userId + ".");
        }
        return Response.ok().entity(deviceHandlerService.getDevice(deviceId)).build();
    }

    @Override
    public Response userIdQrAuthDevicesGet(String userId) {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving all devices of user : " + userId + ".");
        }
        return Response.ok().entity(deviceHandlerService.listDevices()).build();
    }
}
