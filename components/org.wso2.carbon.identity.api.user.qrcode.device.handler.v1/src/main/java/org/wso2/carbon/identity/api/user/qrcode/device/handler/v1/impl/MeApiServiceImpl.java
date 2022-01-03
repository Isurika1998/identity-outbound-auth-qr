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
import org.wso2.carbon.identity.api.user.qrcode.device.common.util.QRDeviceApiConstants;
import org.wso2.carbon.identity.api.user.qrcode.device.handler.v1.MeApiService;
import org.wso2.carbon.identity.api.user.qrcode.device.handler.v1.core.QRDeviceHandlerService;
import org.wso2.carbon.identity.api.user.qrcode.device.handler.v1.model.RegistrationRequestDTO;

import java.text.MessageFormat;
import javax.ws.rs.core.Response;

import static org.wso2.carbon.identity.api.user.common.ContextLoader.buildURIForHeader;

/**
 * Implementation class of QR device Handler User APIs.
 */
public class MeApiServiceImpl implements MeApiService {

    private static final Log log = LogFactory.getLog(MeApiServiceImpl.class);

    @Autowired
    private QRDeviceHandlerService qrDeviceHandlerService;

    @Override
    public Response meQrAuthDevicesDeviceIdDelete(String deviceId) {

        if (log.isDebugEnabled()) {
            log.debug(MessageFormat.format("Removing device : {0} ", deviceId));
        }
        qrDeviceHandlerService.unregisterDevice(deviceId);
        return Response.noContent().build();
    }

    @Override
    public Response meQrAuthDevicesDeviceIdGet(String deviceId) {

        if (log.isDebugEnabled()) {
            log.debug(MessageFormat.format("Fetching data of device : {0}", deviceId));
        }
        return Response.ok().entity(qrDeviceHandlerService.getDevice(deviceId)).build();
    }

    @Override
    public Response meQrAuthDevicesGet() {

        return Response.ok().entity(qrDeviceHandlerService.listDevices()).build();
    }

    @Override
    public Response meQrAuthDevicesPost(RegistrationRequestDTO registrationRequest) {

        if (log.isDebugEnabled() && registrationRequest != null) {
            log.debug("Received registration request from mobile device: "
                    + registrationRequest.getDeviceId() + ".");
        }
        if (registrationRequest != null) {
            qrDeviceHandlerService.registerDevice(registrationRequest);

            String registeredDevicePath = String.format(QRDeviceApiConstants.V1_API_PATH_COMPONENT
                    + QRDeviceApiConstants.QR_AUTH_GET_DEVICE_PATH, registrationRequest.getDeviceId());

            return Response.created(buildURIForHeader(registeredDevicePath)).build();
        } else {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
    }

    @Override
    public Response meQrAuthDiscoveryDataGet() {

        return Response.ok().entity(qrDeviceHandlerService.getDiscoveryData()).build();
    }
}
