package net.christopherschultz.mirth.plugins.auth.mfa;

import java.security.GeneralSecurityException;

import org.apache.log4j.Logger;

import net.christopherschultz.totp.TimeBasedOneTimePassword;

/**
 * Implements a Time-based one time password multi-factor authenticator.
 */
public class TOTPStrategy
    implements MFAStrategy
{
    private Logger logger = Logger.getLogger(this.getClass());

    private static final int DEFAULT_VALID_INTERVALS = 2;

    private int validIntervals = DEFAULT_VALID_INTERVALS;

    @Override
    public String getMFATokenRequiredMessage(OTPConfig config) {
        if(null != config.issuer) {
            return "TOTP token for " + config.issuer;
        } else {
            return "TOTP Token Required";
        }
    }

    @Override
    public boolean isValidMFAToken(OTPConfig config, String token) {
        if(!"totp".equals(config.type))
            throw new IllegalArgumentException("Unsupported OTP type: " + config.type);

//        System.out.println("algo: " + config.algorithm + ", interval=" + config.period + ", length=" + config.digits);

        TimeBasedOneTimePassword totp = new TimeBasedOneTimePassword();
        totp.setHmacAlgorithm("Hmac" + config.algorithm); // oc.algorithm will be e.g. "SHA1", we need e.g. "HmacSHA1"
        totp.setInterval(config.period * 1000l);
        totp.setTokenLength(config.digits);
        totp.setValidIntervals(this.validIntervals);

        try {
            return totp.isTokenValid(config.secret, token);
        } catch (GeneralSecurityException gse) {
            logger.error("Error checking TOTP token", gse);

            return false;
        }
    }
}
