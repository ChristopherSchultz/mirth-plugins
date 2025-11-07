package net.christopherschultz.mirth.plugins.auth.ldap;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

    private final Logger logger = LoggerFactory.getLogger(LDAPAuthenticatorPlugin.class);

    private String _contextFactoryClassName = DEFAULT_CONTEXT_FACTORY_CLASS_NAME;
    private String _url;
    private String _userDNTemplate;
    private String _baseDN;
    private String _groupFilterTemplate;
    private int _retries;
    private long _retryInterval;
    private boolean _fallbackToLocalAuthentication = false;
    private Map<String,String> _usernameMap;
    private Map<String,String> _usernameReverseMap;
    private String _usernameTemplate;
    private Set<String> _nonLDAPUsernames;

    public String getPluginPointName() {
        return "LDAP-Authenticator";
    }

    @Override
    public Properties getDefaultProperties() {
        if(logger.isTraceEnabled()) {
            logger.trace("getDefaultProperties called");
        }

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
        try (InputStream in = getClass().getClassLoader().getResourceAsStream("ldap.properties")) {
            if(null == in) {
                if(logger.isDebugEnabled()) {
                    logger.debug("No local ldap.properties found; using database configuration with " + props.size() + " items");
                }
            } else {
                if(logger.isTraceEnabled()) {
                    logger.trace("Found local ldap.properties file; merging with database configuration");
                }

                localProperties.load(in);

                if(logger.isTraceEnabled()) {
                    logger.trace("Loaded " + localProperties.size() + " items from local ldap.properties; merged with " + props.size() + " items from database");
                }
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
            tries = Integer.parseInt(props.getProperty(Constants.LDAP_RETRIES, String.valueOf(DEFAULT_RETRIES)));
        } catch (NumberFormatException nfe) {
            logger.warn("Invalid value for " + Constants.LDAP_RETRIES + " (" + props.getProperty(Constants.LDAP_RETRIES) + "), falling-back to default value of " + tries);
            // Ignore, use default
        }
        try {
            retryInterval = Long.parseLong(props.getProperty(Constants.LDAP_RETRY_INTERVAL, String.valueOf(DEFAULT_RETRY_INTERVAL)));
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
        setUsernameMap(props.getProperty(Constants.LDAP_USERNAME_MAP, null));
        setUsernameTemplate(props.getProperty(Constants.LDAP_USERNAME_TEMPLATE, null));
        setNonLDAPUsernames(props.getProperty(Constants.LDAP_NON_LDAP_USERNAMES, null));
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

    public String getUsernameTemplate() {
        return _usernameTemplate;
    }

    public void setUsernameTemplate(String template) {
        if(null == template || 0 == template.trim().length() || "{username}".equals(template)) {
            _usernameTemplate = null;
        } else {
            _usernameTemplate = template;
        }
    }

    public void setNonLDAPUsernames(String nonLDAPUsernames) {
        if(null == nonLDAPUsernames) {
            _nonLDAPUsernames = null;
        } else {
            setNonLDAPUsernames(nonLDAPUsernames.split("\\s*,\\s*"));
        }
    }

    public void setNonLDAPUsernames(String[] nonLDAPUsernames) {
        if(null == nonLDAPUsernames || 0 == nonLDAPUsernames.length) {
            _nonLDAPUsernames = null;
        } else if(1 == nonLDAPUsernames.length) {
            _nonLDAPUsernames = Collections.singleton(nonLDAPUsernames[0]);
        } else {
            HashSet<String> usernames = new HashSet<String>(nonLDAPUsernames.length);
            for(String username : nonLDAPUsernames) {
                usernames.add(username);
            }

            _nonLDAPUsernames = Collections.unmodifiableSet(usernames);
        }
    }

    public void setNonLDAPUsernames(Collection<String> nonLDAPUsernames) {
        if(null == nonLDAPUsernames || 0 == nonLDAPUsernames.size()) {
            _nonLDAPUsernames = null;
        } else {
            _nonLDAPUsernames = Collections.unmodifiableSet(new HashSet<String>(nonLDAPUsernames));
        }
    }

    public Set<String> getNonLDAPUsernames() {
        return _nonLDAPUsernames;
    }

    public void setUsernameMap(String mapString) {
        if(null == mapString || 0 == mapString.trim().length()) {
            _usernameMap = null;
            _usernameReverseMap = null;
        } else {
            String[] maps = mapString.split("\\s*(?<!\\\\),\\s*"); // Split on comma using \ as an escape character

            HashMap<String,String> map = new HashMap<String,String>(maps.length);

            for(String mapped: maps) {
                String[] split = mapped.split("\\s*(?<!\\\\)=\\s*"); // Split on equals using \ as an escape character

                if(2 == split.length) {
                    map.put(split[0], split[1]);
                } else {
                    logger.warn("Ignoring confusing mapping: " + mapped);
                }
            }

            _usernameMap = Collections.unmodifiableMap(map);

            map = new HashMap<String,String>();
            for(Map.Entry<String,String> entry : _usernameMap.entrySet()) {
                String oldEntry = map.put(entry.getValue(), entry.getKey());
                if(null != oldEntry) {
                    logger.warn("Username " + entry.getValue() + " is mapped to both " + oldEntry + " and " + entry.getKey());
                }
            }

            _usernameReverseMap = Collections.unmodifiableMap(map);
        }
    }

    public Map<String,String> getUsernameMap() {
        return _usernameMap;
    }

    public Map<String,String> getUsernameReverseMap() {
        return _usernameReverseMap;
    }

    /**
     * Map a user's username from the original user-supplied username
     * to one that should be used when authenticating to LDAP.
     *
     * @param username The username to map.
     *
     * @return The mapped username, which may be unchanged.
     */
    public String mapUsername(String username) {
        if(null == username)
            return null;

        String mappedUsername;

        Map<String,String> map = getUsernameMap();
        if(null != map) {
            mappedUsername = map.get(username);

            if(null == mappedUsername) {
                mappedUsername = username;
            }
        } else {
            mappedUsername = username;
        }

        String template = getUsernameTemplate();
        if(null != template)
            mappedUsername = template.replace("{username}", mappedUsername);

        return mappedUsername;
    }

    /**
     * Unmap a user's username from the one they use for LDAP authentication
     * to their preferred in-Mirth username, if such a thing exists.
     *
     * This allows the user to use either their preferred Mirth username OR
     * their LDAP username to login, and the Mirth username will always
     * end up being the "unmapped" one. This can help prevent duplicate/alias
     * users being created in the Mirth database.
     *
     * @param username The username to unmap.
     *
     * @return The unmapped username, which may be unchanged.
     */
    public String unmapUsername(String username) {
        if(null == username) {
            return null;
        }

        Map<String,String> usernameReverseMap = getUsernameReverseMap();

        String unmappedUsername;
        if(null == usernameReverseMap) {
            unmappedUsername = username;
        } else {
            unmappedUsername = usernameReverseMap.get(username);

            if(null == unmappedUsername) {
                unmappedUsername = username;
            }
        }

        return unmappedUsername;
    }

    public boolean isNonLDAPUsername(String username) {
        Set<String> nonLDAPUsernames = getNonLDAPUsernames();

        return null != nonLDAPUsernames
                && nonLDAPUsernames.contains(username)
                ;
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

        if(isNonLDAPUsername(username)) {
            // Always use the "basic"
            if(logger.isDebugEnabled())
                logger.debug("User " + username + " is a non-LDAP user; falling-back to local authentication");

            return null;
        }

        int tries = getRetries();
        long retryInterval = getRetryInterval();

        String mappedUsername = mapUsername(username);
        if(!username.equals(mappedUsername)) {
            if(logger.isDebugEnabled()) {
                logger.debug("Mapped incoming username from " + username + " to " + mappedUsername);
            }
        }

        while(tries > 0) {
            try {
                // We can either connect with an anonymous and/or admin DN and go
                // from there, or we can connect as the user trying to authenticate.
                //
                // Let's try the direct approach for now.

                User ldapUser = performUserAuthenticationAndAuthorization(mappedUsername, plainPassword);

                if(logger.isTraceEnabled()) {
                    logger.trace("Successfully authenticated user '" + mappedUsername
                                 + "' using server " + getURL());
                }

                // Check to see if we need to create a new local user
                UserController uc = ControllerFactory.getFactory().createUserController();

                // Un-map the username, just in case this is necessary.
                username = unmapUsername(username);

                if(logger.isTraceEnabled()) {
                    logger.trace("Will use the username '" + username + "' for Mirth");
                }

                User user = uc.getUser(null, username);

                if(null == user) {
                    if(logger.isDebugEnabled()) {
                        logger.debug("Must create new local user for '" + username + "'");
                    }

                    uc.updateUser(ldapUser);
                }

                return new LoginStatus(LoginStatus.Status.SUCCESS, null);
            } catch (NamingException ne) {
                if(getFallbackToLocalAuthentication()) {
                    logger.error("Failed to authenticate user '" + mappedUsername
                            + "' using server " + getURL()
                            + "; falling-back to local authentication", ne);

                    return null;
                } else {
                    logger.error("Failed to authenticate user '" + mappedUsername
                            + "' using server " + getURL(), ne);

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
                logger.debug("Failed to authenticate user '" + username
                             + "' using server " + getURL()
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
     * @return The User to use in the Mirth database.
     *
     * @throws NamingException If there is an error
     */
    private User performUserAuthenticationAndAuthorization(String username, String password)
        throws NamingException
    {
        if(null == password || 0 == password.length())
            throw new IllegalArgumentException("Empty password is prohibited");

        if(null == getURL()
           || null == getGroupFilterTemplate()) {
            throw new IllegalStateException("No LDAP URL configured. Missing configuration?");
        }

        String userTemplate = getUserDNTemplate();

        String dn;
        if(null != userTemplate) {
            dn = userTemplate.replace("{username}", escapeFilterValue(username));
        } else {
            dn = escapeFilterValue(username);
        }

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
        sc.setReturningAttributes(new String[] { "dn", "cn", "email", "mail", "emailAddress", "givenName", "sn" });
        sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
        sc.setTimeLimit(10000);

        String filter = getGroupFilterTemplate();
        filter = filter.replace("{username}", escapeFilterValue(username));

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

            User user = new User();
            /*
            user.setEmail(mappedUsername);
            user.setFirstName(mappedUsername);
            user.setLastName(mappedUsername);
*/
            user.setUsername(username);

            return user;
        } else {
            throw new AuthenticationException("User is not in any required group");
        }
    }

    public Map<String, Object> getObjectsForSwaggerExamples() {
        return null;
    }

    /**
     * Filter components need to escape special chars.
     * Note that each piece of the filter needs to be escaped,
     * not the whole filter expression, for example:
     *
     * "(&(cn="+ esc("Admins") +")(member="+ esc("CN=Doe\\, Jöhn,OU=ImPeople,DC=ds,DC=augur,DC=com") +"))"
     *
     * Credit: Chris Janicki [https://stackoverflow.com/a/46008789/276232]
     *
     * @see Oracle Directory Server Enterprise Edition 11g Reference doc
     * @see http://docs.oracle.com/cd/E29127_01/doc.111170/e28969/ds-ldif-search-filters.htm#gdxoy
     * @param s A String field within the search expression
     * @return The escaped string, safe for use in the search expression.
     */
    public static String escapeFilterValue(String s)
    {
        if(s == null) return "";
        StringBuilder sb = new StringBuilder(s.length());
        for (byte c : s.getBytes(StandardCharsets.UTF_8))
        {
            if (c=='\\') { sb.append("\\5c"); }
            else if (c=='*') { sb.append("\\2a"); }
            else if (c=='(') { sb.append("\\28"); }
            else if (c==')') { sb.append("\\29"); }
            else if (c==0) { sb.append("\\00"); }
            else if ((c&0xff)>127) { sb.append("\\").append(to2CharHexString(c)); } // UTF-8's non-7-bit characters, e.g. é, á, etc...
            else { sb.append((char)c); }
        }

        return sb.toString();
    }

    private static final char[] HEX = "0123456789abcdef".toCharArray();
    /**
     * @return The least significant 16 bits as a two-character hex string,
     * padded by a leading '0' if necessary.
     */
    public static String to2CharHexString(int i)
    {
        return new String(new char[] {
                HEX[(i >> 4) & 0x0f],
                HEX[(i     ) & 0x0f],
        });
    }
}
