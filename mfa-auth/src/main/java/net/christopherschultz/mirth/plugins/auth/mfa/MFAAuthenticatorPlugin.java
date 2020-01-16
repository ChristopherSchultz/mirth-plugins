package net.christopherschultz.mirth.plugins.auth.mfa;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;

import com.mirth.connect.client.core.ControllerException;
import com.mirth.connect.model.ExtendedLoginStatus;
import com.mirth.connect.model.ExtensionPermission;
import com.mirth.connect.model.LoginStatus;
import com.mirth.connect.model.User;
import com.mirth.connect.plugins.MultiFactorAuthenticationPlugin;
import com.mirth.connect.server.controllers.ControllerFactory;
import com.mirth.connect.server.controllers.UserController;

/**
 * A multi-factor authentication plug-in supporting TOTP tokens.
 */
public class MFAAuthenticatorPlugin
    extends MultiFactorAuthenticationPlugin
{
    private static final String SIGNING_KEY = "mfa.signing-key";

    private Logger logger = Logger.getLogger(this.getClass());
    private final SecureRandom random = new SecureRandom();
    private byte[] signingKey;
    private long mfaSignatureTimeout = 30 * 1000; // 30 seconds
    private final Map<String,MFAStrategy> strategies;

    public MFAAuthenticatorPlugin() {
        super();

        HashMap<String,MFAStrategy> map = new HashMap<String,MFAStrategy>();
        map.put("totp", new TOTPStrategy());

        strategies = Collections.unmodifiableMap(map);
    }

    @Override
    public void init(Properties properties) {
        if(logger.isTraceEnabled()) {
            logger.trace("Received properties init with " + properties.size() + " properties");
        }

        config(properties);
    }

    @Override
    public void update(Properties properties) {
        if(logger.isTraceEnabled()) {
            logger.trace("Received properties update with " + properties.size() + " properties");
        }

        config(properties);
    }

    private void config(Properties properties) {
        String key = properties.getProperty(SIGNING_KEY, null);

        // TODO: Re-generate signing key if it's missing?
        if(null == key)
            throw new IllegalStateException("Must have " + SIGNING_KEY + " available.");

        this.signingKey = Base64.getUrlDecoder().decode(key);
    }

    /**
     * Returns a set of properties which will be set in the database when
     * the plug-in is first installed.
     */
    @Override
    public Properties getDefaultProperties() {
        if(logger.isTraceEnabled()) {
            logger.trace("getDefaultProperties");
        }

        Properties props = new Properties();

        byte[] signingKey = generateNonce(256);

        String signingKeyString = Base64.getUrlEncoder().encodeToString(signingKey);

        if(logger.isTraceEnabled()) {
            logger.trace("Generated new MFA message-signing key: " + signingKeyString);
        }

        props.setProperty(SIGNING_KEY, signingKeyString);

        return props;
    }

    @Override
    public ExtensionPermission[] getExtensionPermissions() {
        return null;
    }

    @Override
    public String getPluginPointName() {
        return "MFA-Authenticator";
    }

    @Override
    public void start() {
    }

    @Override
    public void stop() {
    }

    @Override
    public LoginStatus authenticate(String username, LoginStatus primaryStatus) {
        if(logger.isTraceEnabled()) {
            logger.trace("Got authentication call: username=" + username + ", status=" + primaryStatus.getStatus() + "/" + primaryStatus.getMessage());
        }

        if(LoginStatus.Status.SUCCESS == primaryStatus.getStatus()
           || LoginStatus.Status.SUCCESS_GRACE_PERIOD == primaryStatus.getStatus()) {
            UserController uc = ControllerFactory.getFactory().createUserController();

            try {
                User user = uc.getUser(null, username);

                if(null == user)
                    throw new IllegalStateException("User " + username + " not found");

                String config = uc.getUserPreference(user.getId(), getMFAUserPreferenceName());

//                if(logger.isTraceEnabled()) {
//                    logger.trace("MFA configuration for " + username + " is " + config);
//                }

                if(null == config) {
                    // Returning the "primary status" here basically skips the MFA step.

                    // TODO: Check to see if MFA is *required* for this user? All users?

                    return primaryStatus;
                } else {
                    /**
                     * This is our only opportunity to pass any data from the
                     * server-side plug-in to the client-side plug-in.
                     *
                     * The client must call login(Username, String userData) to
                     * continue after this point. Note that the password is not
                     * also sent, and the server won't have any access to the
                     * password from any previous authentication-attempt.
                     *
                     * So, we have to send something back to the client
                     * that can be sent back to us proving that they got
                     * this far in the process. Otherwise, the effect will be
                     * that any remote client who can guess the user's current
                     * TOTP token can use it to login directly, without
                     * specifying the password.
                     *
                     * Since we don't have the password, here, we can return
                     * a signed nonce+timestamp as the username and then,
                     * when the client-side plug-in calls authenticate
                     * including the loginData, we can pull this information
                     * out of that blob.
                     *
                     * So the data we return to the client plug-in from here
                     * will include the username, timestmap, and signature.
                     * The client will pass back the username, timestamp,
                     * and signature in addition to the MFA token. We
                     * then validate the signature of the username+timestamp
                     * as well as the timestamp itself and check the MFA token
                     * value.
                     */
                    OTPConfig oc = OTPConfig.parseOTPConfig(config);

                    MFAStrategy strategy = strategies.get(oc.type);

                    if(null == strategy)
                        throw new IllegalStateException("Unrecognized OTP strategy: " + oc.type);

                    String mfaResponseMessage = this.assembleClientResponseMessage(username, strategy.getMFATokenRequiredMessage(oc));

                    if(logger.isTraceEnabled()) {
                        logger.trace("Returning FAIL for more-info-needed for user " + username);
//                        logger.trace("Returning 'message' to client: " + mfaResponseMessage);
                    }

                    // Notify the client that an authentication-plugin must be invoked
                    return new ExtendedLoginStatus(LoginStatus.Status.FAIL, mfaResponseMessage, null, getClientPluginClassName());
                }
            } catch (Exception e) {
                return new LoginStatus(LoginStatus.Status.FAIL, e.getMessage());
            }
        } else {
            // Return primary failure

            return primaryStatus;
        }
    }

    @Override
    public LoginStatus authenticate(String loginData) {
//        if(logger.isTraceEnabled()) {
//            logger.trace("Got authentication call: loginData=" + loginData);
//        }

        MFAData mfaData = parseUserData(loginData);

        UserController uc = ControllerFactory.getFactory().createUserController();

        try {
            User user = uc.getUser(null, mfaData.username);

            if(null == user) {
                if(logger.isTraceEnabled()) {
                    logger.trace("User " + mfaData.username + " does not exist");
                }

                throw new IllegalStateException("User " + mfaData.username + " not found");
            }

            String config = uc.getUserPreference(user.getId(), getMFAUserPreferenceName());

//            if(logger.isTraceEnabled()) {
//                logger.trace("MFA configuration for " + mfaData.username + " is " + config);
//            }

            long now = System.currentTimeMillis();

            if(mfaData.timestamp > now
               || mfaData.timestamp < (now - this.mfaSignatureTimeout)) {
                if(logger.isDebugEnabled()) {
                    logger.debug("MFA signature expired for user " + mfaData.username);
                }

                return new LoginStatus(LoginStatus.Status.FAIL, "Stale MFA signature");
            }

            if(!mfaData.isSignatureValid(getSigningKey())) {
                if(logger.isDebugEnabled()) {
                    logger.debug("MFA signature invalid for user " + mfaData.username);
                }

                return new LoginStatus(LoginStatus.Status.FAIL, "Invalid signature");
            }

            OTPConfig oc = OTPConfig.parseOTPConfig(config);
            MFAStrategy strategy = strategies.get(oc.type);
            if(null == strategy) {
                logger.error("Unrecognized OTP strategy: " + oc.type);

                throw new IllegalStateException("Unrecognized OTP strategy: " + oc.type);
            }

            if(!strategy.isValidMFAToken(oc, mfaData.token)) {
                if(logger.isDebugEnabled()) {
                    logger.debug("MFA token invalid for user " + mfaData.username);
                }

                // TODO: return ExtendedStatus from here?
                return new LoginStatus(LoginStatus.Status.FAIL, "Incorrect MFA token");
            }

            if(logger.isTraceEnabled()) {
                logger.trace("MFA token successfully matched; returning SUCCESS/Ok for user " + mfaData.username);
            }

            return new LoginStatus(LoginStatus.Status.SUCCESS, "Ok");
        } catch (ControllerException ce) {
            logger.warn("Failed to process user login", ce);

            return new LoginStatus(LoginStatus.Status.FAIL, ce.getMessage());
        } catch (NoSuchAlgorithmException nsae) {
            // Shouldn't happen
            logger.error("Cannot check signature", nsae);

            throw new IllegalStateException("Cannot check signature", nsae);
        }
    }

    private byte[] getSigningKey() {
        return this.signingKey;
    }

    private static byte[] getSignature(byte[] key, byte[] nonce, String username, long timestamp) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        // This is lazy. I'm okay with it.
        ByteBuffer dbuf = ByteBuffer.allocate(8);
        dbuf.putLong(timestamp);

        md.update(nonce);
        md.update(dbuf.array());
        md.update(username.getBytes(StandardCharsets.UTF_8));
        md.update(key);

        return md.digest();
    }

    private synchronized byte[] generateNonce(int bytes) {
        byte[] nonce = new byte[12];

        random.nextBytes(nonce);

        return nonce;
    }

    // url(username)&base64(nonce)&timestamp&base64(signature)&authMessage
    private String assembleClientResponseMessage(String username, String authenticationMessage) throws GeneralSecurityException {
        long now = System.currentTimeMillis();

        byte[] nonce = generateNonce(12);

        // TODO: Store nonce + timestamp in user's preferences to prevent replays?

        byte[] sig = getSignature(getSigningKey(), nonce, username, now);

        try {
            return URLEncoder.encode(username, "UTF-8")
                    + '&' + Base64.getUrlEncoder().encodeToString(nonce)
                    + '&' + String.valueOf(now)
                    + '&' + Base64.getUrlEncoder().encodeToString(sig)
                    + '&' + URLEncoder.encode(authenticationMessage, "UTF-8")
                    ;
        } catch (UnsupportedEncodingException uee) {
            throw new InternalError("UTF-8 not supported");
        }
    }

    // url(username)&base64(nonce)&timestamp&base64(signature)&token
    private MFAData parseUserData(String userData) {
        if(null == userData)
            throw new IllegalArgumentException("User data must not be null");

        // Don't parse too much data.
        //
        // max username length (db table) = 40 chars
        // nonce will be 16 chars
        // max timestmap = 9223372036854775807 = 19 chars
        // sha256 signature = 32 bytes = 64 characters
        // 4 ':' characters
        // MFA token lengths are usually short e.g. 6 characters or so
        //
        // A total of 149 characters.
        //
        // 1024 characters should be more than enough.

        if(1024 < userData.length())
            throw new IllegalArgumentException("User data is too long");

        String[] args = userData.split("&", 5);
        if(5 != args.length)
            throw new IllegalArgumentException("Incorrect number of user-data items (" + args.length + ")");

        try {
            return new MFAData(Base64.getUrlDecoder().decode(URLDecoder.decode(args[1], "UTF-8")),
                    URLDecoder.decode(args[0], "UTF-8"),
                    URLDecoder.decode(args[4], "UTF-8"),
                    Long.parseLong(URLDecoder.decode(args[2], "UTF-8")),
                    Base64.getUrlDecoder().decode(URLDecoder.decode(args[3], "UTF-8")));
        } catch (UnsupportedEncodingException uee) {
            throw new InternalError("UTF-8 not supported");
        }
    }

    static class MFAData {
        final byte[] nonce;
        final String username;
        final String token;
        final long timestamp;
        final byte[] signature;

        private MFAData(byte[] nonce, String username, String token, long timestamp, byte[] signature) {
            this.nonce = nonce;
            this.username = username;
            this.token = token;
            this.timestamp = timestamp;
            this.signature = signature;
        }

        public boolean isSignatureValid(byte[] signingKey) throws NoSuchAlgorithmException {
            if(null == this.signature)
                throw new IllegalStateException("No signature available for checking");

            // Re-compute our own signature
            byte[] sig = getSignature(signingKey, nonce, username, timestamp);

            final int length = sig.length;
            if(length != this.signature.length)
                throw new IllegalStateException("Signature lengths differ; mismatched algorithms?");
            if(length < 16)
                throw new IllegalStateException("Signature is too short");

            boolean matches = true;

            for(int i=0; i<length; ++i)
                matches &= (this.signature[i] == sig[i]);

            return matches;
        }
    }

    /**
     * Returns the name of the user preference that contains the user's MFA
     * configuration.
     *
     * @return The name of the user preference that contains the user's MFA
     *         configuration.
     */
    public String getMFAUserPreferenceName() {
        return "net.christopherschultz.mirth.plugins.auth.mfa-config";
    }

    /**
     * Returns the name of the client-side plug-in class. The standard one
     * ought to work for most single-token purposes.
     *
     * @return The name of the client-side plug-in class.
     */
    protected String getClientPluginClassName() {
        // NOTE: Cannot return MFAAuthenticationClientPlugin.class.getName
        // because it will cause CNFE on the server. :(

        return "net.christopherschultz.mirth.plugins.auth.mfa.MFAAuthenticationClientPlugin";
    }
}
