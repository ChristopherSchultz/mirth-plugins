package net.christopherschultz.mirth.plugins.auth.mfa;

import java.awt.Window;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mirth.connect.client.core.Client;
import com.mirth.connect.client.core.ClientException;
import com.mirth.connect.client.core.api.servlets.UserServletInterface;
import com.mirth.connect.plugins.ClientPlugin;
import com.mirth.connect.plugins.MultiFactorAuthenticationClientPlugin;
import com.mirth.connect.model.LoginStatus;
import com.mirth.connect.model.ExtendedLoginStatus;

/**
 * Implements a ClientPlugin for multi-factor authentication.
 *
 * Can support multiple types of multi-factor authentication.
 */
public class MFAAuthenticationClientPlugin
    extends ClientPlugin
    implements MultiFactorAuthenticationClientPlugin
{
    private Logger logger = LoggerFactory.getLogger(this.getClass());

    public MFAAuthenticationClientPlugin() {
        this("default");
    }

    public MFAAuthenticationClientPlugin(String pluginName) {
        super(pluginName);
    }

    @Override
    public LoginStatus authenticate(Window window, Client client, String username, LoginStatus primaryLoginStatus) {
        // primaryLoginStatus will be FAIL with a message.
        // This ExtendedStatus came from the server-side plug-in.
        //
        // It seems that "message" is the only place we can pass information back and forth.
        //
        // So we will get a whole mess of information from the server encoded into the "message" string.

        if(logger.isTraceEnabled()) {
            logger.trace("Got call to authenticate: username=" + username + ", primaryStatus=" + primaryLoginStatus.getStatus()+ "/" + primaryLoginStatus.getMessage());
        }

        // url(username)&base64(nonce)&timestamp&base64(signature)&authMessage
        String[] parts = primaryLoginStatus.getMessage().split("&", 5);
        String message;

        try {
            message = URLDecoder.decode(parts[4], "UTF-8");
        } catch (UnsupportedEncodingException uee) {
            throw new InternalError("UTF-8 is not supported");
        }

        String token = javax.swing.JOptionPane.showInputDialog(window, message, "MFA Token", javax.swing.JOptionPane.QUESTION_MESSAGE);

        if(null != token) {
            // Assemble the userData header-value
            // url(username)&base64(nonce)&timestamp&base64(signature)&token
            String encodedToken;

            try {
                encodedToken = URLEncoder.encode(token, "UTF-8");
            } catch (UnsupportedEncodingException uee) {
                throw new InternalError("UTF-8 not supported");
            }

            String userData = parts[0] + '&' + parts[1] + '&' + parts[2] + '&' + parts[3] + '&' + encodedToken;

            Map<String,List<String>> headers = Collections.singletonMap(UserServletInterface.LOGIN_DATA_HEADER, Collections.singletonList(userData));

            try {
                LoginStatus status = client.getServlet(UserServletInterface.class, null, headers).login(username, null);

                if(logger.isTraceEnabled()) {
                    if(null == status) {
                        logger.trace("Got null login status :(");
                    } else if(status instanceof ExtendedLoginStatus) {
                        logger.trace("Got login status from login() with user-data: " + status + ", status=" + status.getStatus() + ", updatedUsername=" + status.getUpdatedUsername());
                    } else {
                        logger.trace("Got login status from login() with user-data: " + status + ", status=" + status.getStatus() + ", updatedUsername=" + status.getUpdatedUsername() + ", clientPluginClass=" + ((ExtendedLoginStatus)status).getClientPluginClass());
                    }
                }

                return status;
            } catch (ClientException ce) {
                if(logger.isDebugEnabled()) {
                    logger.debug("Caught exception when calling client.login() with user-data", ce);
                }

                return new LoginStatus(LoginStatus.Status.FAIL, ce.getMessage());
            }
        } else {
            if(logger.isTraceEnabled()) {
                logger.trace("User cancelled input dialog, returning FAIL status");
            }

            // Remove the "message" from the server.
            return new LoginStatus(LoginStatus.Status.FAIL, "");
        }
    }

    public String getPluginPointName() {
        return "MFA-Authenticator";
    }

    // used for starting processes in the plugin when the program is started
    public void start() {
        if(logger.isTraceEnabled()) {
            logger.trace("Plug-in starting, name=" + getPluginName());
        }
    }

    // used for stopping processes in the plugin when the program is exited
    public void stop() {};

    // Called when establishing a new session for the user
    public void reset() {}
}

