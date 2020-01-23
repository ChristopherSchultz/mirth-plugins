package net.christopherschultz.mirth.plugins.auth.mfa;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Locale;
import java.util.Objects;

/**
 * Configuration for OTP (one-time password).
 */
public class OTPConfig
{
    // NOTE: DO NOT change these defaults; they are not preferences,
    // but spec-defined defaults.
    private static final String DEFAULT_OTP_HMAC_ALGORITHM = "SHA1";
    private static final int DEFAULT_OTP_DIGITS = 6;
    private static final int DEFAULT_OTP_PERIOD = 30;
    private static final int DEFAULT_OTP_COUNTER = 0;

    protected final String type;
    protected final String issuer;
    protected final String secret;
    protected final String algorithm;
    protected final int digits;
    protected final int period;
    protected final int counter;

    public OTPConfig(String type, String issuer, String secret, String algorithm, int digits, int period, int counter) {
        this.type = type;
        this.issuer = issuer;
        this.secret = secret;
        this.algorithm = algorithm;
        this.digits = digits;
        this.period = period;
        this.counter = counter;
    }

    @Override
    public String toString() {
        try {
            StringBuilder sb = new StringBuilder("otpauth://").append(URLEncoder.encode(type, "UTF-8")).append('/');
            if(null != issuer)
                sb.append(issuer);

            sb.append("?secret=").append(URLEncoder.encode(secret, "UTF-8"));

            if(!Objects.equals(DEFAULT_OTP_HMAC_ALGORITHM, algorithm))
                sb.append("&algorithm=").append(URLEncoder.encode(algorithm, "UTF-8"));

            if(DEFAULT_OTP_DIGITS != digits)
                sb.append("&digits=").append(digits);
            if(DEFAULT_OTP_COUNTER != counter)
                sb.append("&counter=").append(counter);
            if(DEFAULT_OTP_PERIOD != period)
                sb.append("&period=").append(period);

            return sb.toString();
        } catch (UnsupportedEncodingException uee) {
            throw new InternalError("UTF-8 is not supported");
        }
    }

    public static OTPConfig parseOTPConfig(String config) {
        // This URI format is fully-documented here:
        //
        // https://github.com/google/google-authenticator/wiki/Key-Uri-Format
        //
        // Briefly:
        // otpauth://TYPE/LABEL?PARAMETERS
        //
        // type is: hotp, totp
        // label is what should be shown in an authenticator as an auth label
        // recognized parameters are: secret, issuer, algorithm, digits, counter, period
        //
        if(!config.startsWith("otpauth://"))
            throw new IllegalArgumentException("Configuration does not appear to be for OTP-based authentication");

        if(config.length() < 15)
            throw new IllegalArgumentException("Unrecognized otp config format");

        String type = config.substring(10, 14);

        int pos = config.indexOf('?', 15);
        if(0 > pos)
            throw new IllegalArgumentException("Unrecognized otp config format");

        String issuer = config.substring(15, pos);
        if(0 == issuer.length())
            issuer = null;

        String parameterPart = config.substring(pos + 1);

        String[] parameters = parameterPart.split("&");

        HashMap<String,String> params = new HashMap<String,String>(parameters.length);

        for(String param : parameters) {
            String[] s = param.split("=");

            if(null == s || 0 == s.length) {
                // Ignore this "parameter"
            } else if(s.length == 1) {
                params.put(s[0], "");
            } else {
                params.put(s[0], s[1]);
            }
        }
        String secret = params.get("secret");

        if(null == secret)
            throw new IllegalArgumentException("OTP config contains no secret");

        String algorithm = params.get("algorithm");
        if(null == algorithm)
            algorithm = DEFAULT_OTP_HMAC_ALGORITHM;
        else if(!algorithm.toLowerCase(Locale.ENGLISH).startsWith("hmac"))
            algorithm = DEFAULT_OTP_HMAC_ALGORITHM;

        int digits = DEFAULT_OTP_DIGITS;
        int period = DEFAULT_OTP_PERIOD;
        int counter = DEFAULT_OTP_COUNTER;

        if(null != params.get("digits"))
            digits = Integer.parseInt(params.get("digits"));
        if(null != params.get("period"))
            period = Integer.parseInt(params.get("period"));
        if(null != params.get("counter"))
            counter = Integer.parseInt(params.get("counter"));

        if(period < 10)
            period = 10;
        if(period > 120)
            period = 120;

        if(digits < 6)
            digits = 6;
        if(digits > 20)
            digits = 20;

        return new OTPConfig(type, issuer, secret, algorithm, digits, period, counter);
    }
}