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

package org.wso2.carbon.identity.api.user.qrcode.device.handler.v1.core;

import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.api.user.qrcode.device.common.QRDeviceHandlerServiceHolder;
import org.wso2.carbon.identity.api.user.qrcode.device.common.util.QRDeviceApiConstants;
import org.wso2.carbon.identity.api.user.qrcode.device.common.util.QRDeviceApiUtils;
import org.wso2.carbon.identity.api.user.qrcode.device.handler.v1.model.DeviceDTO;
import org.wso2.carbon.identity.api.user.qrcode.device.handler.v1.model.DiscoveryDataDTO;
import org.wso2.carbon.identity.api.user.qrcode.device.handler.v1.model.PatchDTO;
import org.wso2.carbon.identity.api.user.qrcode.device.handler.v1.model.RegistrationRequestDTO;
import org.wso2.carbon.identity.application.authenticator.qrcode.common.QRJWTValidator;
import org.wso2.carbon.identity.application.authenticator.qrcode.common.exception.IdentityQRAuthException;
import org.wso2.carbon.identity.application.authenticator.qrcode.device.handler.exception.QRDeviceHandlerClientException;
import org.wso2.carbon.identity.application.authenticator.qrcode.device.handler.exception.QRDeviceHandlerServerException;
import org.wso2.carbon.identity.application.authenticator.qrcode.device.handler.model.Device;
import org.wso2.carbon.identity.application.authenticator.qrcode.device.handler.model.RegistrationDiscoveryData;
import org.wso2.carbon.identity.application.authenticator.qrcode.device.handler.model.RegistrationRequest;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;

import java.util.ArrayList;
import java.util.List;

/**
 * Service class of qr device handler Rest APIs.
 */
public class QRDeviceHandlerService {

    /**
     * Register a new device.
     *
     * @param registrationRequestDTO Registration request
     */
    public void registerDevice(RegistrationRequestDTO registrationRequestDTO) {

        RegistrationRequest registrationRequest = new RegistrationRequest();
        try {
            registrationRequest.setDeviceId(registrationRequestDTO.getDeviceId());
            registrationRequest.setDeviceModel(registrationRequestDTO.getModel());
            registrationRequest.setDeviceName(registrationRequestDTO.getName());
            registrationRequest.setPublicKey(registrationRequestDTO.getPublicKey());
            registrationRequest.setPushId(registrationRequestDTO.getPushId());
            registrationRequest.setSignature(registrationRequestDTO.getSignature());
            QRDeviceHandlerServiceHolder.getQRDeviceHandlerService().registerDevice(registrationRequest);

        } catch (QRDeviceHandlerClientException e) {
            throw QRDeviceApiUtils.handleException(
                    QRDeviceApiConstants.ErrorMessages.ERROR_CODE_REGISTER_DEVICE_CLIENT_ERROR, e);
        } catch (QRDeviceHandlerServerException e) {
            throw QRDeviceApiUtils.handleException(
                    QRDeviceApiConstants.ErrorMessages.ERROR_CODE_REGISTER_DEVICE_SERVER_ERROR, e);
        }
    }

    /**
     * Remove a registered device via MyAccount.
     *
     * @param deviceId Unique ID for the device to be removed
     */
    public void unregisterDevice(String deviceId) {

        try {
            QRDeviceHandlerServiceHolder.getQRDeviceHandlerService().unregisterDevice(deviceId);
        } catch (QRDeviceHandlerClientException e) {
            throw QRDeviceApiUtils.handleException(
                    QRDeviceApiConstants.ErrorMessages.ERROR_CODE_UNREGISTER_DEVICE_CLIENT_ERROR, e, deviceId);
        } catch (QRDeviceHandlerServerException e) {
            throw QRDeviceApiUtils.handleException(
                    QRDeviceApiConstants.ErrorMessages.ERROR_CODE_UNREGISTER_DEVICE_SERVER_ERROR, e, deviceId);
        }
    }

    /**
     * Remove a registered device via mobile app.
     *
     * @param deviceId Unique ID for the device
     * @param token    JWT containing device removal information
     */
    public void unregisterDeviceMobile(String deviceId, String token) {

        QRJWTValidator validator = new QRJWTValidator();
        try {
            String publicKey = QRDeviceHandlerServiceHolder.getQRDeviceHandlerService().getPublicKey(deviceId);

            if (validator.getValidatedClaimSet(token, publicKey) != null) {
                QRDeviceHandlerServiceHolder.getQRDeviceHandlerService().unregisterDevice(deviceId);
            }
        } catch (QRDeviceHandlerServerException e) {
            throw QRDeviceApiUtils.handleException(
                    QRDeviceApiConstants.ErrorMessages.ERROR_CODE_UNREGISTER_DEVICE_SERVER_ERROR, e, deviceId);
        } catch (QRDeviceHandlerClientException e) {
            throw QRDeviceApiUtils.handleException(
                    QRDeviceApiConstants.ErrorMessages.ERROR_CODE_UNREGISTER_DEVICE_CLIENT_ERROR, e, deviceId);
        } catch (IdentityQRAuthException e) {
            throw QRDeviceApiUtils.handleException(
                    QRDeviceApiConstants.ErrorMessages.ERROR_CODE_INVALID_SIGNATURE, e, deviceId);
        }
    }

    /**
     * Update attributes of a registered device.
     *
     * @param deviceId      Unique ID of the device
     * @param patchDTOArray Array of PatchDTO objects
     */
    public void editDevice(String deviceId, List<PatchDTO> patchDTOArray) {

        try {
            QRDeviceHandlerServiceHolder.getQRDeviceHandlerService().getDevice(deviceId);
            for (PatchDTO patch: patchDTOArray) {
                String operation = patch.getOperation();
                if (operation.equals(QRDeviceApiConstants.OPERATION_REPLACE) &&
                        (patch.getPath().equals(QRDeviceApiConstants.PATH_DEVICE_NAME) ||
                                patch.getPath().equals(QRDeviceApiConstants.PATH_PUSH_ID))) {
                    QRDeviceHandlerServiceHolder.getQRDeviceHandlerService()
                            .editDevice(deviceId, patch.getPath(), patch.getValue());
                } else {
                    throw QRDeviceApiUtils.handleException(
                            QRDeviceApiConstants.ErrorMessages.ERROR_CODE_EDIT_DEVICE_CLIENT_ERROR, deviceId);
                }
            }
        } catch (QRDeviceHandlerServerException e) {
            throw QRDeviceApiUtils.handleException(
                    QRDeviceApiConstants.ErrorMessages.ERROR_CODE_EDIT_DEVICE_SERVER_ERROR, e, deviceId);
        } catch (QRDeviceHandlerClientException e) {
            throw QRDeviceApiUtils.handleException(
                    QRDeviceApiConstants.ErrorMessages.ERROR_CODE_GET_DEVICE_CLIENT_ERROR, e, deviceId);
        }
    }

    /**
     * Get a registered device.
     *
     * @param deviceId Unique ID of the required device
     * @return Device object
     */
    public DeviceDTO getDevice(String deviceId) {

        try {
            Device device = QRDeviceHandlerServiceHolder.getQRDeviceHandlerService().getDevice(deviceId);
            DeviceDTO deviceDTO = new DeviceDTO();
            deviceDTO.setDeviceId(device.getDeviceId());
            deviceDTO.setName(device.getDeviceName());
            deviceDTO.setModel(device.getDeviceModel());
            deviceDTO.setPushId(device.getPushId());
            deviceDTO.setRegistrationTime(device.getRegistrationTime());
            deviceDTO.setLastUsedTime(device.getLastUsedTime());
            return deviceDTO;
        } catch (QRDeviceHandlerClientException e) {
            throw QRDeviceApiUtils.handleException(
                    QRDeviceApiConstants.ErrorMessages.ERROR_CODE_GET_DEVICE_CLIENT_ERROR, e, deviceId);
        } catch (QRDeviceHandlerServerException e) {
            throw QRDeviceApiUtils.handleException(
                    QRDeviceApiConstants.ErrorMessages.ERROR_CODE_GET_DEVICE_SERVER_ERROR, e, deviceId);
        }
    }

    /**
     * Get a list of all the devices for the authenticated in user.
     *
     * @return List of registered devices of the user
     */
    public List<DeviceDTO> listDevices() {

        List<Device> devices;
        User user = getAuthenticatedUser();

        try {
            String userId = getUserIdFromUsername(user.getUserName());
            devices = QRDeviceHandlerServiceHolder.getQRDeviceHandlerService().listDevices(userId);

            List<DeviceDTO> deviceDTOArrayList = new ArrayList<>();
            DeviceDTO deviceDTO;
            if (devices != null) {
                for (Device device : devices) {
                    deviceDTO = new DeviceDTO();
                    deviceDTO.setDeviceId(device.getDeviceId());
                    deviceDTO.setName(device.getDeviceName());
                    deviceDTO.setModel(device.getDeviceModel());
                    deviceDTO.setRegistrationTime(device.getRegistrationTime());
                    deviceDTO.setLastUsedTime(device.getLastUsedTime());
                    deviceDTOArrayList.add(deviceDTO);
                }
            }

            return deviceDTOArrayList;
        } catch (QRDeviceHandlerServerException e) {
            throw QRDeviceApiUtils.handleException(
                    QRDeviceApiConstants.ErrorMessages.ERROR_CODE_LIST_DEVICE_SERVER_ERROR, e);
        } catch (UserStoreException e) {
            throw QRDeviceApiUtils.handleException(
                    QRDeviceApiConstants.ErrorMessages.ERROR_CODE_USER_STORE_ERROR, e);
        }
    }

    /**
     * Get discovery data for registering a new device.
     *
     * @return Discovery data
     */
    public DiscoveryDataDTO getDiscoveryData() {

        RegistrationDiscoveryData discoveryData;
        try {
            discoveryData = QRDeviceHandlerServiceHolder.getQRDeviceHandlerService()
            .getRegistrationDiscoveryData();

            DiscoveryDataDTO discoveryDataDTO = new DiscoveryDataDTO();
            discoveryDataDTO.setDid(discoveryData.getDeviceId());
            discoveryDataDTO.setUn(discoveryData.getUsername());
            discoveryDataDTO.setTd(discoveryData.getTenantDomain());
            discoveryDataDTO.setFn(discoveryData.getFirstName());
            discoveryDataDTO.setLn(discoveryData.getLastName());
            discoveryDataDTO.setChg(discoveryData.getChallenge());
            discoveryDataDTO.setHst(discoveryData.getHost());
            discoveryDataDTO.setBp(discoveryData.getBasePath());
            discoveryDataDTO.setRe(discoveryData.getRegistrationEndpoint());
            discoveryDataDTO.setRde(discoveryData.getRemoveDeviceEndpoint());
            discoveryDataDTO.setAe(discoveryData.getAuthenticationEndpoint());

            return discoveryDataDTO;
        } catch (QRDeviceHandlerServerException e) {
            throw QRDeviceApiUtils.handleException(
                    QRDeviceApiConstants.ErrorMessages.ERROR_CODE_REGISTER_DEVICE_SERVER_ERROR, e);
        }
    }

    /**
     * Get the authenticated user.
     *
     * @return Authenticated user
     */
    private User getAuthenticatedUser() {

        User user = User.getUserFromUserName(CarbonContext.getThreadLocalCarbonContext().getUsername());
        user.setTenantDomain(CarbonContext.getThreadLocalCarbonContext().getTenantDomain());
        return user;
    }

    /**
     * Get the unique ID for a user by the username.
     *
     * @param username Username of the user
     * @return UserID for the user
     * @throws UserStoreException if an error occurs when getting the userstore manager
     */
    private String getUserIdFromUsername(String username) throws UserStoreException {

        AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) CarbonContext.
                getThreadLocalCarbonContext().getUserRealm().getUserStoreManager();
        return userStoreManager.getUserIDFromUserName(username);
    }
}
