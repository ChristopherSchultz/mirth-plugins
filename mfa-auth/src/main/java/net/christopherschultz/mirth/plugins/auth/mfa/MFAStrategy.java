package net.christopherschultz.mirth.plugins.auth.mfa;

/**
 * An MFA strategy which understands how to validate a specific type of MFA
 * token.
 */
public interface MFAStrategy {
    /**
     * Return a message to send to the client requesting the MFA token.
     *
     * @return A message to send to the client.
     */
    public String getMFATokenRequiredMessage(OTPConfig config);

    /**
     * Checks to see if the MFA token is valid.
     *
     * @param config The MFA config.
     * @param token  The token from the user.
     *
     * @return <code>true</code> if the MFA token is valid, or <code>false</code> if
     *         the token is not valid.
     */
    public boolean isValidMFAToken(OTPConfig config, String token);
}