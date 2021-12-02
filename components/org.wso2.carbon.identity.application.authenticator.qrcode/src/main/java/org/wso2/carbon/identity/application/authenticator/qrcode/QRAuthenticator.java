/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.application.authenticator.qrcode;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundConstants;
import org.wso2.carbon.identity.application.authenticator.qrcode.common.QRAuthContextManager;
import org.wso2.carbon.identity.application.authenticator.qrcode.common.QRJWTValidator;
import org.wso2.carbon.identity.application.authenticator.qrcode.common.exception.QRAuthTokenValidationException;
import org.wso2.carbon.identity.application.authenticator.qrcode.common.impl.QRAuthContextManagerImpl;
import org.wso2.carbon.identity.application.authenticator.qrcode.dto.AuthDataDTO;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.text.ParseException;


/**
 * QR code based custom Authenticator
 */
public class QRAuthenticator extends AbstractApplicationAuthenticator implements LocalApplicationAuthenticator {

    private static final long serialVersionUID = 4345354156955223654L;
    private static final Log log = LogFactory.getLog(QRAuthenticator.class);

    @Override
    public boolean canHandle(HttpServletRequest request) {

        return request.getParameter(QRAuthenticatorConstants.PROCEED_AUTH) != null;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        String sessionDataKey = request.getParameter(InboundConstants.RequestProcessor.CONTEXT_KEY);
       // String sessionDataKey = "123456234";

        String retryParam = "";

        if (context.isRetrying()) {
            retryParam = "&authFailure=true&authFailureMsg=login.fail.message";
        }

        redirectQRPage(response, sessionDataKey);

    }

    protected void redirectQRPage(HttpServletResponse response, String sessionDataKey)
            throws AuthenticationFailedException {

        try {
            String qrPage = ServiceURLBuilder.create().addPath(QRAuthenticatorConstants.QR_PAGE)
                    .addParameter("sessionDataKey", sessionDataKey).build().getAbsolutePublicURL();
           // QRUtil.generateQRCode(sessionDataKey);
            response.sendRedirect(qrPage);
        } catch (IOException e) {
            String errorMessage = String.format("Error occurred when trying to to redirect user to the login page.");
            throw new AuthenticationFailedException(errorMessage, e);
        } catch (URLBuilderException e) {
            String errorMessage = String.format("Error occurred when building the URL for the login page for user.");
            throw new AuthenticationFailedException(errorMessage, e);
        }
    }

    /**
     * This method is used to process the authentication response.
     * Inside here we check if this is a authentication request coming from oidc flow and then check if the user is
     * in the 'photoSharingRole'.
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        QRAuthContextManager contextManager = new QRAuthContextManagerImpl();
        AuthenticationContext sessionContext = contextManager.getContext(request
                .getParameter(QRAuthenticatorConstants.SESSION_DATA_KEY));
        AuthDataDTO authDataDTO = (AuthDataDTO) sessionContext
                .getProperty(QRAuthenticatorConstants.CONTEXT_AUTH_DATA);

        String authResponseToken = authDataDTO.getAuthToken();

        String deviceId = getDeviceIdFromToken(authResponseToken);
       // String publicKey = getPublicKey(deviceId);

        QRJWTValidator validator = new QRJWTValidator();
        JWTClaimsSet claimsSet;

    }

    /**
     * Derive the Device ID from the auth response token header.
     *
     * @param token Auth response token
     * @return Device ID
     * @throws AuthenticationFailedException if the token string fails to parse to JWT
     */
    protected String getDeviceIdFromToken(String token) throws AuthenticationFailedException {

        try {
            return String.valueOf(JWTParser.parse(token).getHeader()
                    .getCustomParam(QRAuthenticatorConstants.TOKEN_DEVICE_ID));
        } catch (ParseException e) {
            throw new AuthenticationFailedException("Error occurred when trying to get the device ID from the "
                    + "auth response token.", e);
        }
    }

    @Override
    protected boolean retryAuthenticationEnabled() {
        return true;
    }

    @Override
    public String getFriendlyName() {

        //Set the name to be displayed in local authenticator drop down lsit
        return QRAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {

        return httpServletRequest.getParameter("sessionDataKey");
    }

    @Override
    public String getName() {

        return QRAuthenticatorConstants.AUTHENTICATOR_NAME;
    }
}
