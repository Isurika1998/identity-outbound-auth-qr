/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.qrcode.common.QRAuthContextManager;
import org.wso2.carbon.identity.application.authenticator.qrcode.common.QRJWTValidator;
import org.wso2.carbon.identity.application.authenticator.qrcode.common.exception.IdentityQRAuthException;
import org.wso2.carbon.identity.application.authenticator.qrcode.common.impl.QRAuthContextManagerImpl;
import org.wso2.carbon.identity.application.authenticator.qrcode.dto.AuthDataDTO;
import org.wso2.carbon.identity.application.authenticator.qrcode.internal.QRAuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.AuthenticationResult;
import org.wso2.carbon.user.core.constants.UserCoreClaimConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;
import java.text.ParseException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * QR code based custom authenticator.
 */
public class QRAuthenticator extends AbstractApplicationAuthenticator implements LocalApplicationAuthenticator {

    private static final long serialVersionUID = 4345354156955223654L;
    private static final Log log = LogFactory.getLog(QRAuthenticator.class);

    /**
     * @param request The http servlet request.
     * @return true, if PROCEED_AUTH is not null.
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {

        return request.getParameter(QRAuthenticatorConstants.PROCEED_AUTH) != null;
    }

    /**
     * Initiate authentication request.
     *
     * @param request  The request.
     * @param response The response.
     * @param context  The authentication context.
     * @throws AuthenticationFailedException If unable to redirect user to login page.
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        QRAuthContextManager contextManager = new QRAuthContextManagerImpl();
        String sessionDataKey = request.getParameter(InboundConstants.RequestProcessor.CONTEXT_KEY);

        AuthDataDTO authDataDTO = new AuthDataDTO();
        context.setProperty(QRAuthenticatorConstants.CONTEXT_AUTH_DATA, authDataDTO);
        contextManager.storeContext(sessionDataKey, context);

        redirectQRPage(response, sessionDataKey);
    }

    /**
     * Redirect user to QR code page for login.
     *
     * @param response The response.
     * @param sessionDataKey The session data key.
     * @throws AuthenticationFailedException  If unable to redirect user to login page.
     */
    private void redirectQRPage(HttpServletResponse response, String sessionDataKey)
            throws AuthenticationFailedException {

        try {
            String qrPage = ServiceURLBuilder.create().addPath(QRAuthenticatorConstants.QR_PAGE)
                    .addParameter(QRAuthenticatorConstants.SESSION_DATA_KEY, sessionDataKey).build()
                    .getAbsolutePublicURL();
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
     * This method is overridden to check validation of the given token and authenticate user.
     *
     * @param request  The http servlet request.
     * @param response The http servlet response.
     * @param context  AuthenticationContext.
     * @throws AuthenticationFailedException Authentication process failed for user.
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        QRAuthContextManager contextManager = new QRAuthContextManagerImpl();
        AuthenticationContext sessionContext = contextManager.getContext(request
                .getParameter(QRAuthenticatorConstants.SESSION_DATA_KEY));
        AuthDataDTO authDataDTO = (AuthDataDTO) sessionContext
                .getProperty(QRAuthenticatorConstants.CONTEXT_AUTH_DATA);

        String authResponseToken = authDataDTO.getAuthToken();

        String deviceId = getDeviceIdFromToken(authResponseToken);
       // String publicKey = getPublicKey(deviceId);
        String publicKey = "public key";
        QRJWTValidator validator = new QRJWTValidator();
        JWTClaimsSet claimsSet;

        try {
            claimsSet = validator.getValidatedClaimSet(authResponseToken, publicKey);
        } catch (IdentityQRAuthException e) {
            String errorMessage = String
                    .format("Error occurred when trying to validate the JWT signature from device: %s.", deviceId);
            throw new AuthenticationFailedException(errorMessage, e);
        }
        if (claimsSet != null) {

            String authStatus =
                    getClaimFromClaimSet(claimsSet, QRAuthenticatorConstants.TOKEN_RESPONSE, deviceId);

            if (authStatus.equals(QRAuthenticatorConstants.AUTH_REQUEST_STATUS_SUCCESS)) {
//                context.setProperty(QRAuthenticatorConstants.USER_NAME,
//                        getClaimFromClaimSet(claimsSet, QRAuthenticatorConstants.TOKEN_USER_NAME, deviceId));
                String username = getClaimFromClaimSet(claimsSet, QRAuthenticatorConstants.TOKEN_USER_NAME, deviceId);
                String password = "isurika123";
                String requestTenantDomain = MultitenantUtils.getTenantDomain(username);
                String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
                AbstractUserStoreManager userStoreManager = getUserStoreManager(username, requestTenantDomain);
                AuthenticationResult authenticationResult;
//                try {
//                    authenticationResult = userStoreManager
//                            .authenticateWithID(UserCoreClaimConstants.USERNAME_CLAIM_URI,
//                            tenantAwareUsername, password, UserCoreConstants.DEFAULT_PROFILE);
//                    AuthenticatedUser authenticatedUser = new AuthenticatedUser(authenticationResult
//                    .getAuthenticatedUser().get());
//                    context.setSubject(authenticatedUser);
//                } catch (UserStoreException e) {
//                    e.printStackTrace();
//                }

            } else {
                String errorMessage = String.format("Authentication failed! Auth status for user" +
                        " '%s' is not available in JWT.",
                        getClaimFromClaimSet(claimsSet, QRAuthenticatorConstants.TOKEN_USER_NAME, deviceId));
                throw new AuthenticationFailedException(errorMessage);
            }
        } else {
            String errorMessage = String
                    .format("Authentication failed! JWT signature is not valid for device: %s", deviceId);
            throw new AuthenticationFailedException(errorMessage);
        }
        contextManager.clearContext(getClaimFromClaimSet(claimsSet,
                QRAuthenticatorConstants.TOKEN_SESSION_DATA_KEY, deviceId));
    }

    /**
     * Derive the Device ID from the auth response token header.
     *
     * @param token Auth response token.
     * @return Device ID.
     * @throws AuthenticationFailedException if the token string fails to parse to JWT.
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

    /**
     * Get JWT claim from the claim set.
     *
     * @param claimsSet JWT claim set.
     * @param claim     Required claim.
     * @param deviceId  Device ID.
     * @return Claim string.
     * @throws AuthenticationFailedException if an error occurs while getting a claim.
     */
    protected String getClaimFromClaimSet(JWTClaimsSet claimsSet, String claim, String deviceId)
            throws AuthenticationFailedException {

        try {
            return claimsSet.getStringClaim(claim);
        } catch (ParseException e) {
            String errorMessage = String.format("Failed to get %s from the auth response token received from device: "
                    + "%s.", claim, deviceId);
            throw new AuthenticationFailedException(errorMessage, e);
        }
    }

    private AbstractUserStoreManager getUserStoreManager(String username, String tenantDomain)
            throws AuthenticationFailedException {

        try {
            int tenantId =
                    QRAuthenticatorServiceComponent.getRealmService().getTenantManager().getTenantId(tenantDomain);
            UserRealm userRealm = QRAuthenticatorServiceComponent.getRealmService().getTenantUserRealm(tenantId);
            if (userRealm != null) {
                return (AbstractUserStoreManager) userRealm.getUserStoreManager();
            } else {
                throw new AuthenticationFailedException("Cannot find the user realm for the given tenant: " +
                        tenantId, User.getUserFromUserName(username));
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("Can't find the UserStoreManager for the user: " + username, e);
            }
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

    /**
     * Check whether status of retrying authentication.
     *
     * @return true, if retry authentication is enabled.
     */
    @Override
    protected boolean retryAuthenticationEnabled() {

        return true;
    }

    /**
     * Get friendly name.
     *
     * @return Authenticator friendly name.
     */
    @Override
    public String getFriendlyName() {

        return QRAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get requested session ID.
     *
     * @param request The http servlet request.
     * @return Requested session ID.
     */
    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        return request.getParameter("sessionDataKey");
    }

    /**
     * Get authenticator name.
     *
     * @return Authenticator name.
     */
    @Override
    public String getName() {

        return QRAuthenticatorConstants.AUTHENTICATOR_NAME;
    }
}
