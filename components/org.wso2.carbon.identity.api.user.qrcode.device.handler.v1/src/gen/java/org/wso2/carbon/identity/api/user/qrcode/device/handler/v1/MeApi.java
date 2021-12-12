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

package org.wso2.carbon.identity.api.user.qrcode.device.handler.v1;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import org.springframework.beans.factory.annotation.Autowired;

import org.wso2.carbon.identity.api.user.qrcode.device.handler.v1.model.DeviceDTO;
import org.wso2.carbon.identity.api.user.qrcode.device.handler.v1.model.DiscoveryDataDTO;
import org.wso2.carbon.identity.api.user.qrcode.device.handler.v1.model.ErrorDTO;
import org.wso2.carbon.identity.api.user.qrcode.device.handler.v1.model.RegistrationRequestDTO;

import javax.validation.Valid;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;

/**
 * MeAPI.
 */
@Path("/me")
@Api(description = "The me API")

public class MeApi  {

    @Autowired
    private MeApiService delegate;

    @Valid
    @DELETE
    @Path("/qr-auth/devices/{deviceId}")
    
    @Produces({ "application/json" })
    @ApiOperation(value = "Remove a registered device. ", notes = "This API is used to remove a registered device. ",
            response = Void.class, authorizations = {
        @Authorization(value = "BasicAuth"),
        @Authorization(value = "OAuth2", scopes = {
            
        })
    }, tags = { "me" })
    @ApiResponses(value = { 
        @ApiResponse(code = 204, message = "The device was removed", response = Void.class),
        @ApiResponse(code = 401, message = "Unauthorized", response = Void.class),
        @ApiResponse(code = 403, message = "Forbidden", response = Void.class),
        @ApiResponse(code = 500, message = "Server Error", response = ErrorDTO.class)
    })
    public Response meQrAuthDevicesDeviceIdDelete(@ApiParam(value = "Unique ID of the device", required = true)
                                                      @PathParam("deviceId") String deviceId) {

        return delegate.meQrAuthDevicesDeviceIdDelete(deviceId);
    }

    @Valid
    @GET
    @Path("/qr-auth/devices/{deviceId}")
    
    @Produces({ "application/json" })
    @ApiOperation(value = "Get a registered device. ",
            notes = "This API is used to get a specific registered device. ",
            response = DeviceDTO.class, authorizations = {
        @Authorization(value = "BasicAuth"),
        @Authorization(value = "OAuth2", scopes = {
            
        })
    }, tags = { "me" })
    @ApiResponses(value = { 
        @ApiResponse(code = 200, message = "Requested registered device of the authenticated user",
                response = DeviceDTO.class),
        @ApiResponse(code = 401, message = "Unauthorized", response = Void.class),
        @ApiResponse(code = 403, message = "Forbidden", response = Void.class),
        @ApiResponse(code = 404, message = "Not Found", response = ErrorDTO.class),
        @ApiResponse(code = 500, message = "Server Error", response = ErrorDTO.class)
    })
    public Response meQrAuthDevicesDeviceIdGet(@ApiParam(value = "ID of the device to return", required = true)
                                                   @PathParam("deviceId") String deviceId) {

        return delegate.meQrAuthDevicesDeviceIdGet(deviceId);
    }

    @Valid
    @GET
    @Path("/qr-auth/devices")
    
    @Produces({ "application/json" })
    @ApiOperation(value = "Get list of registered devices. ",
            notes = "This API is used to get a list of registered devices of the authenticated user. ",
            response = Object.class, responseContainer = "List", authorizations = {
        @Authorization(value = "BasicAuth"),
        @Authorization(value = "OAuth2", scopes = {
            
        })
    }, tags = { "me" })
    @ApiResponses(value = { 
        @ApiResponse(code = 200, message = "List of registered devices of the user.",
                response = Object.class, responseContainer = "List"),
        @ApiResponse(code = 401, message = "Unauthorized", response = Void.class),
        @ApiResponse(code = 403, message = "Forbidden", response = Void.class),
        @ApiResponse(code = 500, message = "Server Error", response = ErrorDTO.class)
    })
    public Response meQrAuthDevicesGet() {

        return delegate.meQrAuthDevicesGet();
    }

    @Valid
    @POST
    @Path("/qr-auth/devices")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @ApiOperation(value = "Register a device. ", notes = "This API is used to register a device.<br/> ",
            response = Void.class, authorizations = {
        @Authorization(value = "BasicAuth"),
        @Authorization(value = "OAuth2", scopes = {
            
        })
    }, tags = { "me" })
    @ApiResponses(value = { 
        @ApiResponse(code = 201, message = "Registered a new device", response = Void.class),
        @ApiResponse(code = 400, message = "Bad Request", response = ErrorDTO.class),
        @ApiResponse(code = 401, message = "Unauthorized", response = Void.class),
        @ApiResponse(code = 403, message = "Forbidden", response = Void.class),
        @ApiResponse(code = 409, message = "Conflict", response = ErrorDTO.class),
        @ApiResponse(code = 500, message = "Server Error", response = ErrorDTO.class)
    })
    public Response meQrAuthDevicesPost(@ApiParam(value = "Request sent by a device for registration.",
            required = true) @Valid RegistrationRequestDTO registrationRequestDTO) {

        return delegate.meQrAuthDevicesPost(registrationRequestDTO);
    }

    @Valid
    @GET
    @Path("/qr-auth/discovery-data")
    
    @Produces({ "application/json" })
    @ApiOperation(value = "Generate data for device registration. ",
            notes = "This API is used to generate discovery data for the device registration QR code. ",
            response = DiscoveryDataDTO.class, authorizations = {
        @Authorization(value = "BasicAuth"),
        @Authorization(value = "OAuth2", scopes = {
            
        })
    }, tags = { "me" })
    @ApiResponses(value = { 
        @ApiResponse(code = 200, message = "Successfully generated registration discovery data",
                response = DiscoveryDataDTO.class),
        @ApiResponse(code = 401, message = "Unauthorized", response = Void.class),
        @ApiResponse(code = 403, message = "Forbidden", response = Void.class),
        @ApiResponse(code = 500, message = "Internal Server Error", response = ErrorDTO.class)
    })
    public Response meQrAuthDiscoveryDataGet() {

        return delegate.meQrAuthDiscoveryDataGet();
    }
}
