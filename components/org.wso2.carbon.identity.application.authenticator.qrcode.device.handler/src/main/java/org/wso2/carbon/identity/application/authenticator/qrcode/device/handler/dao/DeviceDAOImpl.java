/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.application.authenticator.qrcode.device.handler.dao;

//import org.apache.commons.logging.Log;
//import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authenticator.qrcode.device.handler.DeviceHandlerConstants;
import org.wso2.carbon.identity.application.authenticator.qrcode.device.handler.model.Device;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * This class implements DeviceDAO interface .
 */
public class DeviceDAOImpl implements DeviceDAO {
   // private static final Log log = LogFactory.getLog(DeviceDAOImpl.class);

    @Override
    public void registerDevice(Device device) throws SQLException {

        Connection connection = IdentityDatabaseUtil.getDBConnection(true);
        PreparedStatement preparedStatement = null;
        try {
            preparedStatement = connection.prepareStatement(DeviceHandlerConstants.SQLQueries.REGISTER_DEVICE);
            preparedStatement.setString(1, device.getDeviceId());
            preparedStatement.setString(2, device.getUserId());
            preparedStatement.setString(3, device.getDeviceName());
            preparedStatement.setString(4, device.getDeviceModel());
            preparedStatement.setString(5, device.getPushId());
            preparedStatement.setString(6, device.getPublicKey());
            preparedStatement.setTimestamp(7, new Timestamp(new Date().getTime()));
            preparedStatement.setTimestamp(8, new Timestamp(new Date().getTime()));
            preparedStatement.executeUpdate();
            if (!connection.getAutoCommit()) {
                connection.commit();
            }
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, preparedStatement);
        }
    }

    @Override
    public void unregisterDevice(String deviceId) throws SQLException {

        Connection connection = IdentityDatabaseUtil.getDBConnection(true);
        PreparedStatement preparedStatement = null;
        try {
            preparedStatement = connection.prepareStatement(DeviceHandlerConstants.SQLQueries.UNREGISTER_DEVICE);
            preparedStatement.setString(1, deviceId);
            preparedStatement.executeUpdate();
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, preparedStatement);
        }
    }

    @Override
    public void deleteAllDevicesOfUser(String userId) throws SQLException {

        Connection connection = IdentityDatabaseUtil.getDBConnection(true);
        PreparedStatement preparedStatement = null;
        try {
            preparedStatement = connection.prepareStatement(DeviceHandlerConstants.SQLQueries.REMOVE_USER_DEVICES);
            preparedStatement.setString(1, userId);
            preparedStatement.executeUpdate();
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, preparedStatement);
        }
    }

    @Override
    public void editDevice(String deviceId, Device updatedDevice) throws SQLException {

        Connection connection = IdentityDatabaseUtil.getDBConnection(true);
        PreparedStatement preparedStatement = null;
        try {
            preparedStatement = connection.prepareStatement(DeviceHandlerConstants.SQLQueries.EDIT_DEVICE);
            preparedStatement.setString(1, updatedDevice.getDeviceName());
            preparedStatement.setString(2, updatedDevice.getPushId());
            preparedStatement.setString(3, deviceId);
            preparedStatement.executeUpdate();
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, preparedStatement);
        }

    }

    @Override
    public Optional<Device> getDevice(String deviceId) throws SQLException {

        Connection connection = IdentityDatabaseUtil.getDBConnection(true);
        PreparedStatement preparedStatement = null;
        Device device = null;
        ResultSet resultSet = null;
        try {
            preparedStatement = connection.prepareStatement(DeviceHandlerConstants.SQLQueries.GET_DEVICE);
            preparedStatement.setString(1, deviceId);
            resultSet = preparedStatement.executeQuery();
            if (resultSet.next()) {
                device = new Device();
                device.setDeviceId(resultSet.getString(DeviceHandlerConstants.DEVICE_ID));
                device.setDeviceName(resultSet.getString(DeviceHandlerConstants.DEVICE_NAME));
                device.setDeviceModel(resultSet.getString(DeviceHandlerConstants.DEVICE_MODEL));
                device.setPushId(resultSet.getString(DeviceHandlerConstants.PUSH_ID));
                device.setPublicKey(resultSet.getString(DeviceHandlerConstants.PUBLIC_KEY));
                device.setRegistrationTime(timestampToDate(resultSet.
                        getTimestamp(DeviceHandlerConstants.REGISTRATION_TIME)));
                device.setLastUsedTime(timestampToDate(resultSet.getTimestamp(DeviceHandlerConstants.LAST_USED_TIME)));
            }
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, preparedStatement);
        }

        return Optional.ofNullable(device);
    }

    @Override
    public List<Device> listDevices(String userId) throws SQLException {

        List<Device> devices = new ArrayList<>();
        Connection connection = IdentityDatabaseUtil.getDBConnection(true);
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;
        try {
            Device device;
            preparedStatement = connection.prepareStatement(DeviceHandlerConstants.SQLQueries.LIST_DEVICES);
            preparedStatement.setString(1, userId);
            resultSet = preparedStatement.executeQuery();
            while (resultSet.next()) {
                device = new Device();
                device.setDeviceId(resultSet.getString(DeviceHandlerConstants.DEVICE_ID));
                device.setDeviceName(resultSet.getString(DeviceHandlerConstants.DEVICE_NAME));
                device.setDeviceModel(resultSet.getString(DeviceHandlerConstants.DEVICE_MODEL));
                device.setRegistrationTime(timestampToDate(resultSet
                        .getTimestamp(DeviceHandlerConstants.REGISTRATION_TIME)));
                device.setLastUsedTime(timestampToDate(resultSet.getTimestamp(DeviceHandlerConstants.LAST_USED_TIME)));
                devices.add(device);
            }
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, preparedStatement);
        }

        return devices;
    }

    @Override
    public Optional<String> getPublicKey(String deviceId) throws SQLException {

        Connection connection = IdentityDatabaseUtil.getDBConnection(true);
        PreparedStatement preparedStatement = null;
        String publicKey = null;
        ResultSet resultSet = null;

        try {
            preparedStatement = connection.prepareStatement(DeviceHandlerConstants.SQLQueries.GET_PUBLIC_KEY);
            preparedStatement.setString(1, deviceId);
            resultSet = preparedStatement.executeQuery();
            if (resultSet.next()) {
                publicKey = (resultSet.getString(DeviceHandlerConstants.PUBLIC_KEY));
            }
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, preparedStatement);
        }

        return Optional.ofNullable(publicKey);
    }

    /**
     * Convert timestamp to date type.
     *
     * @param timestamp Timestamp object
     * @return Date object
     */
    private Date timestampToDate(Timestamp timestamp) {

        return new Date(timestamp.getTime());
    }
}
