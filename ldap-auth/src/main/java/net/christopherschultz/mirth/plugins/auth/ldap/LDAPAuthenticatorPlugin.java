package net.christopherschultz.mirth.plugins.auth.ldap;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.swing.JOptionPane;

import org.apache.log4j.Logger;

import com.mirth.connect.client.core.ControllerException;
import com.mirth.connect.plugins.AuthorizationPlugin;
import com.mirth.connect.plugins.ServicePlugin;
import com.mirth.connect.server.controllers.ControllerFactory;
import com.mirth.connect.server.controllers.UserController;
import com.mirth.connect.model.ExtensionPermission;
import com.mirth.connect.model.LoginStatus;
import com.mirth.connect.model.User;

/**
 * An LDAP authenticator for Mirth Connect.
 *
 */
public class LDAPAuthenticatorPlugin
    implements AuthorizationPlugin, ServicePlugin
{
    private static final String DEFAULT_CONTEXT_FACTORY_CLASS_NAME = "com.sun.jndi.ldap.LdapCtxFactory";
    private static final int DEFAULT_RETRIES = 3;
    private static final int MAX_RETRIES = 100;
    private static final long DEFAULT_RETRY_INTERVAL = 1000;
    private static final long MAX_RETRY_INTERVAL = 10000;

    private final Logger logger = Logger.getLogger(LDAPAuthenticatorPlugin.class);

    private String _contextFactoryClassName = DEFAULT_CONTEXT_FACTORY_CLASS_NAME;
    private String _url;
    private String _userDNTemplate;
    private String _baseDN;
    private String _groupFilterTemplate;
    private int _retries;
    private long _retryInterval;
    private boolean _fallbackToLocalAuthentication = false;

    public String getPluginPointName() {
        return "LDAP-Authenticator";
    }

    @Override
    public Properties getDefaultProperties() {
        return new Properties();
    }

    @Override
    public ExtensionPermission[] getExtensionPermissions() {
        return null;
    }

    @Override
    public void init(Properties props) {
        Properties localProperties = new Properties(props);
        // Load the configuration from ldap.properties and return it.
        // This will cause Mirth Connect to load the properties into the server
        // database and load them out again
        try (InputStream in = getClass().getClassLoader().getResourceAsStream("ldap.properties")) {
            if(null == in) {
                logger.debug("No local ldap.properties found; using database configuration");
            } else {
                localProperties.load(in);
            }
        } catch (IOException ioe) {
            logger.error("Failed to read LDAP configuration from ldap.properties", ioe);
        }

        configure(localProperties);
    }

    private void configure(Properties props) {
        int tries = DEFAULT_RETRIES;
        long retryInterval = DEFAULT_RETRY_INTERVAL;
        try {
            tries = Integer.parseInt(props.getProperty(Constants.LDAP_RETRIES));
        } catch (NumberFormatException nfe) {
            logger.warn("Invalid value for " + Constants.LDAP_RETRIES + " (" + props.getProperty(Constants.LDAP_RETRIES) + "), falling-back to default value of " + tries);
            // Ignore, use default
        }
        try {
            retryInterval = Long.parseLong(props.getProperty(Constants.LDAP_RETRY_INTERVAL));
        } catch (NumberFormatException nfe) {
            logger.warn("Invalid value for " + Constants.LDAP_RETRY_INTERVAL + " (" + props.getProperty(Constants.LDAP_RETRY_INTERVAL) + "), falling-back to default value of " + retryInterval);
            // Ignore, use default
        }

        // Sanity-checks
        if(tries < 1)
            tries = 1;
        else if(tries > MAX_RETRIES)
            tries = MAX_RETRIES;
        if(retryInterval < 0)
            retryInterval = 0;
        else if(retryInterval > MAX_RETRY_INTERVAL)
            retryInterval = MAX_RETRY_INTERVAL;

        setContextFactoryClassName(props.getProperty(Constants.LDAP_CONTEXT_FACTORY_CLASS_NAME, DEFAULT_CONTEXT_FACTORY_CLASS_NAME));
        setURL(props.getProperty(Constants.LDAP_URL, null));
        setBaseDN(props.getProperty(Constants.LDAP_BASE_DN, null));
        setUserDNTemplate(props.getProperty(Constants.LDAP_USER_DN_TEMPLATE, null));
        setGroupFilterTemplate(props.getProperty(Constants.LDAP_GROUP_FILTER, null));
        setRetries(tries);
        setRetryInterval(retryInterval);
        setFallbackToLocalAuthentication(isBooleanTrue(props.getProperty(Constants.LDAP_FALLBACK_TO_LOCAL)));
    }

    public static boolean isBooleanTrue(String s) {
        return "true".equalsIgnoreCase(s)
                || "yes".equalsIgnoreCase(s)
                ;
    }
    @Override
    public void update(Properties props) {
        init(props);
    }

    public void start() {
    }

    public void stop() {
    }

    public void setContextFactoryClassName(String className) {
        _contextFactoryClassName = className;

    }
    public String getContextFactoryClassName() {
        return _contextFactoryClassName;
    }

    public void setURL(String url) {
        _url = url;
    }

    public String getURL() {
        return _url;
    }

    public void setBaseDN(String baseDN) {
        _baseDN = baseDN;
    }

    public String getBaseDN() {
        return _baseDN;
    }

    public void setUserDNTemplate(String template) {
        _userDNTemplate = template;
    }

    public String getUserDNTemplate() {
        return _userDNTemplate;
    }

    public void setGroupFilterTemplate(String template) {
        _groupFilterTemplate = template;
    }

    public String getGroupFilterTemplate() {
        return _groupFilterTemplate;
    }
    public void setRetries(int retries) {
        if(retries < 1 || retries > MAX_RETRIES)
            throw new IllegalArgumentException("Illegal retry value: " + retries);

        _retries = retries;
    }

    public int getRetries() {
        return _retries;
    }

    public void setRetryInterval(long retryInterval) {
        if(retryInterval < 0 || retryInterval > MAX_RETRY_INTERVAL)
            throw new IllegalArgumentException("Illegal retry interval: " + retryInterval);

        _retryInterval = retryInterval;
    }

    public long getRetryInterval() {
        return _retryInterval;
    }

    public void setFallbackToLocalAuthentication(boolean fallback) {
        _fallbackToLocalAuthentication = fallback;
    }

    public boolean getFallbackToLocalAuthentication() {
        return _fallbackToLocalAuthentication;
    }


    /**
     * Authenticates the user against the LDAP server.
     *
     * If {@link #getFallbackToLocalAuthentication()} is <code>true</code>,
     * then authentication failures will return in this method returning
     * <code>null</code> which will cause Mirth to perform local-database
     * authentication.
     *
     * @return SUCCESS if the user was correctly authenticated, or either
     *         FAIL if the authentication or <code>null</code> if the
     *         authentication failed, depending upon the value of
     *         {@link #getFallbackToLocalAuthentication()}.
     */
    public LoginStatus authorizeUser(String username, String plainPassword) throws ControllerException {
        int tries = getRetries();
        long retryInterval = getRetryInterval();

        while(tries > 0) {
            try {
                // We can either connect with an anonymous and/or admin DN and go
                // from there, or we can connect as the user trying to authenticate.
                //
                // Let's try the direct approach for now.

                performUserAuthenticationAndAuthorization(username, plainPassword);

                if(logger.isTraceEnabled()) {
                    logger.trace("Successfully authenticated " + username
                                 + " using server " + getURL());
                }

                // Check to see if we need to create a new local user
                UserController uc = ControllerFactory.getFactory().createUserController();

                User user = uc.getUser(null, username);

                if(null == user) {
                    if(logger.isDebugEnabled()) {
                        logger.debug("Must create new local user for " + username);
                    }

                    user = new User();

                    user.setUsername(username);

                    uc.updateUser(user);
                }

                return new LoginStatus(LoginStatus.Status.SUCCESS, null);
            } catch (NamingException ne) {
                if(getFallbackToLocalAuthentication()) {
                    if(logger.isDebugEnabled())
                        logger.debug("Failed to authenticate " + username
                                     + " using server " + getURL()
                                     + "; falling-back to local authentication", ne);

                    return null;
                } else {
                    if(logger.isTraceEnabled())
                        logger.trace("Failed to authenticate " + username
                                     + " using server " + getURL(), ne);

                    return new LoginStatus(LoginStatus.Status.FAIL, ne.getMessage());
                }
            } catch (Exception e) {
                logger.error("Error during LDAP authentication attempt; re-trying", e);
            }
            tries--;
            try { Thread.sleep(retryInterval); } catch (InterruptedException ie) { }
        }

        // Authentication did not succeed after X tries
        if(getFallbackToLocalAuthentication()) {
            if(logger.isDebugEnabled())
                logger.debug("Failed to authenticate " + username
                             + " using server " + getURL()
                             + "; falling-back to local authentication");

            return null;
        } else {
            return new LoginStatus(LoginStatus.Status.FAIL, null);
        }
    }

    /**
     * Authenticates against an LDAP server using the user's credentials directly.
     *
     * The username should be "bare" and will be converted into a dn by using
     * the {@link #LDAP_USER_DN_TEMPLATE}.
     *
     * @param username The user's username
     * @param password The user's password
     *
     * @return The username to use in the Mirth database
     *
     * @throws NamingException If there is an error
     */
    private String performUserAuthenticationAndAuthorization(String username, String password)
        throws NamingException
    {
        if(null == password || 0 == password.length())
            throw new IllegalArgumentException("Empty password is prohibited");

        String userTemplate = getUserDNTemplate();
        String dn = userTemplate.replace("{username}", username);

        Properties props = new Properties();

        props.put(Context.INITIAL_CONTEXT_FACTORY, getContextFactoryClassName());
        props.put(Context.PROVIDER_URL, getURL());
        props.put(Context.SECURITY_PRINCIPAL, dn);
        props.put(Context.SECURITY_CREDENTIALS, password);

        // TODO: Allow custom TLS configuration
//        props.put("java.naming.ldap.factory.socket","com.eterra.security.authz.dao.CustomSSLSocketFactory" );

        if(logger.isTraceEnabled()) {
            logger.trace("Connecting to LDAP URL " + getURL() + " as " + dn);
        }

        LdapContext ctx = new InitialLdapContext(props, null);
        // throws AuthenticationException if bad password
        // throws javax.naming.CommunicationException comm problem

        SearchControls sc = new SearchControls();
        sc.setReturningAttributes(new String[] { "dn", "cn" });
        sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
        sc.setTimeLimit(10000);

        String filter = getGroupFilterTemplate();
        filter = filter.replace("{username}", username);

        if(logger.isTraceEnabled()) {
            logger.trace("Searching for groups using using filter=" + filter);
        }

        NamingEnumeration<SearchResult> results = ctx.search(getBaseDN(), filter, sc);

        // We only care if at least one result is present
        if(results.hasMore()) {
            if(logger.isTraceEnabled()) {
                while(results.hasMore()) {
                    SearchResult result = results.next();
                    logger.trace("LDAP User " + dn + " is in group " + result.getNameInNamespace());
                }
            }

            return username;
        } else {
            throw new AuthenticationException("User is not in any required group");
        }
    }

    public static void main(String[] args) throws Exception {
        String password = JOptionPane.showInputDialog("Password");

        LDAPAuthenticatorPlugin lap = new LDAPAuthenticatorPlugin();
        lap.init(lap.getDefaultProperties());
        lap.performUserAuthenticationAndAuthorization("schultz", password);
    }
}
