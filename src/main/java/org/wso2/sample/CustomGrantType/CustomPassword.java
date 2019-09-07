package org.wso2.sample.CustomGrantType;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.PasswordGrantHandler;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;

public class CustomPassword extends PasswordGrantHandler {
    private static Log log = LogFactory.getLog(CustomPassword.class);

    @Override
    public OAuth2AccessTokenRespDTO issue(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
        log.info("Executing the issue() method");
        OAuthAppDO appInfo;
        OAuthAppDAO oAuthAppDAO = new OAuthAppDAO();
        try {
            appInfo = oAuthAppDAO.getAppInformation(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId());
            if(appInfo.getApplicationName().equals("admin_SampleApp_PRODUCTION")) {    // Name of the Application
                tokReqMsgCtx.setValidityPeriod(86400);
            }
        } catch (InvalidOAuthClientException e) {
            e.printStackTrace();
        }
        OAuth2AccessTokenRespDTO tokenRespDTO =  super.issue(tokReqMsgCtx);

        return tokenRespDTO;
    }
}
