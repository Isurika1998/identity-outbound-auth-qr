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
 */

package org.wso2.carbon.identity.application.authenticator.qrcode.device.handler.exception;

/**
 * QR device handler server exception class .
 */
public class QRDeviceHandlerServerException extends QRDeviceHandlerException {

    private static final long serialVersionUID = -3791909577807841657L;

    public QRDeviceHandlerServerException(String message) {

        super(message);
    }

    public QRDeviceHandlerServerException(String errorCode, String message) {

        super(errorCode, message);
    }

    public QRDeviceHandlerServerException(String message, Throwable cause) {

        super(message, cause);
    }

    public QRDeviceHandlerServerException(String errorCode, String message, Throwable cause) {

        super(errorCode, message, cause);
    }
}