package net.christopherschultz.mirth.plugins.auth.ldap;

public interface Constants
{
    public static final String LDAP_URL = "ldap.url";
    public static final String LDAP_USER_DN_TEMPLATE = "ldap.user-dn-template";
    public static final String LDAP_GROUP_FILTER = "ldap.group-filter";
    public static final String LDAP_BASE_DN = "ldap.base-dn";
    public static final String LDAP_RETRIES = "ldap.retries";
    public static final String LDAP_RETRY_INTERVAL = "ldap.retry-interval";
    public static final String LDAP_FALLBACK_TO_LOCAL = "ldap.fallback-to-local-authentication";
    public static final String LDAP_CONTEXT_FACTORY_CLASS_NAME = "ldap.context-factory-class-name";
    public static final String LDAP_USERNAME_MAP = "ldap.username-map";
    public static final String LDAP_USERNAME_TEMPLATE = "ldap.username-template";
    public static final String LDAP_NON_LDAP_USERNAMES = "ldap.non-ldap-usernames";
}