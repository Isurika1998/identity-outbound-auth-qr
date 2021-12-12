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
import org.wso2.carbon.identity.api.user.qrcode.device.handler.v1.model.ErrorDTO;

import javax.validation.Valid;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;

/**
 * DefaultAPI.
 */
@Path("/")
@Api(description = "The  API")

public class DefaultApi  {

    @Autowired
    private DefaultApiService delegate;

    @Valid
    @DELETE
    @Path("/{userId}/qr-auth/devices/{deviceId}")
    
    @Produces({ "application/json" })
    @ApiOperation(value = "Remove a device by the device ID. ",
            notes = "This API is used by an admin to remove a registered device by the device ID.<br/>" +
                    " <b>Permission required:</b>" +
                    " <br>   * /permission/admin/manage/identity/user/qr_device_mgt/delete <br/>" +
                    " <b>Scopes required:</b>" +
                    " <br>   * internal_qr_device_delete ", response = Void.class, authorizations = {
        @Authorization(value = "BasicAuth"),
        @Authorization(value = "OAuth2", scopes = {
            
        })
    }, tags = { "admin" })
    @ApiResponses(value = { 
        @ApiResponse(code = 204, message = "Device was removed", response = Void.class),
        @ApiResponse(code = 401, message = "Unauthorized", response = Void.class),
        @ApiResponse(code = 403, message = "Forbidden", response = Void.class),
        @ApiResponse(code = 500, message = "Server Error", response = ErrorDTO.class)
    })
    public Response userIdQrAuthDevicesDeviceIdDelete(@ApiParam(value = "Unique ID of the user", required = true)
                                                          @PathParam("userId") String userId,
                                                      @ApiParam(value = "Unique ID of device", required = true)
                                                      @PathParam("deviceId") String deviceId) {

        return delegate.userIdQrAuthDevicesDeviceIdDelete(userId,  deviceId);
    }

    @Valid
    @GET
    @Path("/{userId}/qr-auth/devices/{deviceId}")
    
    @Produces({ "application/json" })
    @ApiOperation(value = "Get a device by the device ID. ",
            notes = "This API is used by an admin to retrieve a registered device by the device ID.<br/>" +
                    " <b>Permission required:</b>  * /permission/admin/manage/identity/user/qr_device_mgt/view <br/>" +
                    " <b>Scopes required:</b> * internal_qr_device_view ",
            response = DeviceDTO.class, authorizations = {
        @Authorization(value = "BasicAuth"),
        @Authorization(value = "OAuth2", scopes = {
            
        })
    }, tags = { "admin" })
    @ApiResponses(value = { 
        @ApiResponse(code = 200, message = "Requested device of the user", response = DeviceDTO.class),
        @ApiResponse(code = 401, message = "Unauthorized", response = Void.class),
        @ApiResponse(code = 403, message = "Forbidden", response = Void.class),
        @ApiResponse(code = 404, message = "Not Found", response = ErrorDTO.class),
        @ApiResponse(code = 500, message = "Server Error", response = ErrorDTO.class)
    })
    public Response userIdQrAuthDevicesDeviceIdGet(@ApiParam(value = "Unique ID of the user'", required = true)
                                                       @PathParam("userId") String userId,
                                                   @ApiParam(value = "ID of the device to return", required = true)
                                                   @PathParam("deviceId") String deviceId) {

        return delegate.userIdQrAuthDevicesDeviceIdGet(userId,  deviceId);
    }

    @Valid
    @GET
    @Path("/{userId}/qr-auth/devices")
    
    @Produces({ "application/json" })
    @ApiOperation(value = "Get user's registered device list. ",
            notes = "This API is used by admins to get a list of devices registered under a user.<br/>" +
                    " <b>Permission required:</b>  * /permission/admin/manage/identity/user/qr_device_mgt/list <br/>" +
                    " <b>Scopes required:</b> * internal_qr_device_list ",
            response = Object.class, responseContainer = "List", authorizations = {
        @Authorization(value = "BasicAuth"),
        @Authorization(value = "OAuth2", scopes = {
            
        })
    }, tags = { "admin" })
    @ApiResponses(value = { 
        @ApiResponse(code = 200, message = "List of registered devices of the user",
                response = Object.class, responseContainer = "List"),
        @ApiResponse(code = 401, message = "Unauthorized", response = Void.class),
        @ApiResponse(code = 403, message = "Forbidden", response = Void.class),
        @ApiResponse(code = 404, message = "Not Found", response = ErrorDTO.class),
        @ApiResponse(code = 500, message = "Server Error", response = ErrorDTO.class)
    })
    public Response userIdQrAuthDevicesGet(@ApiParam(value = "Unique ID of a user", required = true)
                                               @PathParam("userId") String userId) {

        return delegate.userIdQrAuthDevicesGet(userId);
    }

}
