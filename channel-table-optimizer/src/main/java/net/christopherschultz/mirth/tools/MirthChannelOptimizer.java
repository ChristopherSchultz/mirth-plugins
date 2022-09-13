/**
 * Copyright (C) 2022 Christopher Schultz.
 *
 * This software is distributed "AS IS", without any warranties of any kind.
 * Running this software could potentially damage your Mirth installation
 * or database. You assume all responsibility for your own property, both
 * real and virtual.
 *
 * This software is licensed under the Apache Software License 2.0.
 * A copy of this license should have been provided with this software.
 * If not, you may obtain a copy of the AL2 at this address:
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package net.christopherschultz.mirth.tools;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.Console;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import net.christopherschultz.util.TLSUtils;

/**
 * Optimizes the underlying databases for a Mirth channel.
 *
 * @author Christopher Schultz
 */
public class MirthChannelOptimizer {
    public static void usage(PrintStream out) {
        out.println("Usage: java " + MirthChannelOptimizer.class.getName() + " [options] channel [channel...]");
        out.println();
        out.println("Optimizes the database tables which support a Mirth channel.");
        out.println();
        out.println("Options:");
        out.println();
        out.println("  -c, --config       file     A file that contains connection and authentication info.");
        out.println("  -U, --jdbcurl      url      JDBC URL to use to connect to the database.");
        out.println("  -u, --jdbcuser     user     JDBC username to use.");
        out.println("  -p, --jdbcpassword password JDBC username to use. (Potentially dangerous. Use -P)");
        out.println("  -R, --apiurl       url      Base endpoint for the Mirth API. Should end in '/api'");
        out.println("  -s, --apiuser      user     Mirth API username to use.");
        out.println("  -a, --apipassword  password Mirth API password to use. (Potentially dangerous. Use -P)");
        out.println("  -P, --ask-password          Prompts for any required passwords.");
        out.println("  -t, --timeout      timeout  Timeout in seconds for JDBC queries. (Default: no timeout)");
        out.println();
        out.println("Channels can be specified by name, channel-id (GUID), or numeric local channel id.");
    }

    public static void main(String[] args) throws Exception {
        MirthChannelOptimizer mco = new MirthChannelOptimizer();

        int argindex = 0;
        boolean promptForPasswords = false;
        while(argindex < args.length) {
            String arg = args[argindex++];

            if("--jdbcuser".equals(arg) || "-u".equals(arg)) {
                mco.setJDBCUsername(args[argindex++]);
            } else if("--jdbcpassword".equals(arg) || "-p".equals(arg)) {
                mco.setJDBCPassword(args[argindex++]);
            } else if("--jdbcurl".equals(arg) || "-U".equals(arg)) {
                mco.setJDBCURL(args[argindex++]);
            } else if("--apiuser".equals(arg) || "-s".equals(arg)) {
                mco.setAPIUsername(args[argindex++]);
            } else if("--apipassword".equals(arg) || "-a".equals(arg)) {
                mco.setAPIPassword(args[argindex++]);
            } else if("--apiurl".equals(arg) || "-R".equals(arg)) {
                mco.setAPIEndpoint(args[argindex++]);
            } else if("--askpassword".equals(arg) || "-P".equals(arg)) {
                promptForPasswords = true;
            } else if("--timeout".equals(arg) || "-t".equals(arg)) {
                mco.setQueryTimeout(Integer.parseInt(args[argindex++]));
            } else if("--config".equals(arg) || "-c".equals(arg)) {
                config(args[argindex++], mco);
            } else if("--help".equals(arg) || "-h".equals(arg)) {
                usage(System.out);
                System.exit(0);
            } else if("--".equals(arg)) {
                break;
            } else {
                // Assume we are done with options
                argindex--; // Rewind
                break;
            }
        }

        if(null == mco.getJDBCURL()) {
            System.err.println("A JDBC URL is required");
            System.err.println();
            usage(System.err);
            System.exit(1);
        }

        if(promptForPasswords) {
            Console console = System.console();
            if(null == console) {
                throw new IllegalStateException("Cannot read password(s) securely from console.");
            }

            if(null != mco.getJDBCUsername() && null == mco.getJDBCPassword()) {
                char[] pwd = console.readPassword("Please enter the password for " + mco.getJDBCURL() + " user " + mco.getJDBCUsername());
                mco.setJDBCPassword(new String(pwd));
            }

            if(null != mco.getAPIUsername() && null == mco.getAPIPassword()) {
                char[] pwd = console.readPassword("Please enter the password for " + mco.getAPIEndpoint() + " user " + mco.getAPIUsername());
                mco.setAPIPassword(new String(pwd));
            }
        }

        while(argindex < args.length) {
            mco.optimizeChannelTables(args[argindex++]);
        }
    }

    // Super simple
    private static void config(String filename, MirthChannelOptimizer mco) throws IOException {
        try(BufferedReader in = new BufferedReader(new InputStreamReader(new FileInputStream(filename), Charset.defaultCharset()))) {
            mco.setJDBCURL(nullBlank(in.readLine()));
            mco.setJDBCUsername(nullBlank(in.readLine()));
            mco.setJDBCPassword(nullBlank(in.readLine()));
            mco.setAPIEndpoint(nullBlank(in.readLine()));
            mco.setAPIUsername(nullBlank(in.readLine()));
            mco.setAPIPassword(nullBlank(in.readLine()));
        }
    }

    private static String nullBlank(String s) {
        if(null == s) {
            return null;
        }
        s = s.trim();
        if(0 == s.length()) {
            return null;
        }
        return s;
    }

    private String jdbcURL;
    private String jdbcUsername;
    private String jdbcPassword;
    private Integer queryTimeout;

    private String apiEndpoint;
    private String apiUsername;
    private String apiPassword;

    public String getJDBCURL() { return jdbcURL; }
    public void setJDBCURL(String jdbcURL) { this.jdbcURL = jdbcURL; }
    public String getJDBCUsername() { return jdbcUsername; }
    public void setJDBCUsername(String jdbcUsername) { this.jdbcUsername = jdbcUsername; }
    public String getJDBCPassword() { return jdbcPassword; }
    public void setJDBCPassword(String jdbcPassword) { this.jdbcPassword = jdbcPassword; }
    public Integer getQueryTimeout() { return queryTimeout; }
    public void setQueryTimeout(Integer timeout) { this.queryTimeout = timeout; }

    public String getAPIEndpoint() { return apiEndpoint; }
    public void setAPIEndpoint(String apiEndpoint) {
        if(apiEndpoint.endsWith("/")) {
            apiEndpoint = apiEndpoint.substring(0, apiEndpoint.length() - 1);
        }

        this.apiEndpoint = apiEndpoint;
    }
    public String getAPIUsername() { return apiUsername; }
    public void setAPIUsername(String apiUsername) { this.apiUsername = apiUsername; }
    public String getAPIPassword() { return apiPassword; }
    public void setAPIPassword(String apiPassword) { this.apiPassword = apiPassword; }

    private static class ConnectionWrapper implements Closeable {
        HttpURLConnection conn;
        String encoding;
        InputStream in;

        public ConnectionWrapper(HttpURLConnection conn) {
            this.conn = conn;
        }

        public int getResponseCode() throws IOException { return conn.getResponseCode(); }

        public InputStream getInputStream() {
            if(null == in) {
                try {
                    in = conn.getInputStream();
                } catch (IOException ioe) {
                    in = conn.getErrorStream();
                }
            }
            return in;
        }

        public String getContentType() { return conn.getContentType(); }
        public String getEncoding() {
            if(null == encoding) {
                this.encoding = getCharacterEncoding(getContentType(), "ISO-8859-1");
            }
            return encoding;
        }

        public long getContentLengthLong() { return conn.getContentLengthLong(); }
        public int getContentLength() { return conn.getContentLength(); }

        @Override
        public void close() throws IOException {
            if(null != in) {
                in.close();
            }
            if(null != conn) {
                conn.disconnect();
            }
        }

        /**
         * A regular expression pattern to discover a "charset" parameter
         * embedded in a MIME type.
         */
        private static Pattern CONTENT_TYPE_CHARSET_MATCHER
            = Pattern.compile("text/.+;[\\s]*charset=([^ ]+)");

        private String getCharacterEncoding(String contentType, String defaultEncoding) {
            Matcher m = CONTENT_TYPE_CHARSET_MATCHER.matcher(contentType);
            if(m.matches()) {
                return m.group(1);
            } else {
                return defaultEncoding;
            }
        }
}

    private ConnectionWrapper makeAPICall(String method, String url, String entity) throws IOException, GeneralSecurityException {
        if(!url.startsWith("/")) {
            throw new IllegalArgumentException("URL must be relative and start with a /");
        }

        URL u = new URL(getAPIEndpoint() + url);

        URLConnection conn = u.openConnection();
        if(!(conn instanceof HttpURLConnection)) {
            throw new IOException("Expected HttpURLConnection, got " + conn.getClass().getName());
        }
        HttpURLConnection hc = (HttpURLConnection)conn;

        hc.setRequestMethod(method);
        if(hc instanceof HttpsURLConnection) {
            SSLSocketFactory ssf = TLSUtils.getSSLSocketFactory(null, "TLS", null, null, null, TLSUtils.getTrustAllCertsTrustManagers(), null);
            ((HttpsURLConnection)hc).setSSLSocketFactory(ssf);
        }
        hc.setRequestProperty("Authorization", "Basic " + Base64.getEncoder().encodeToString((getAPIUsername() + ":" + getAPIPassword()).getBytes("UTF-8")));
        hc.setRequestProperty("X-Requested-With", "OpenAPI");
        hc.setRequestProperty("Accept", "application/xml");

        if(null != entity) {
            hc.setRequestProperty("Content-Type", "application/xml");
            hc.setDoOutput(true);
        }

        hc.connect();

        if(null != entity) {
            try(OutputStream out = hc.getOutputStream()) {
                out.write(entity.getBytes("UTF-8"));
                out.flush();
            }
        }

        return new ConnectionWrapper(hc);
    }

    private static void dump(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[4096];
        int c;
        while(-1 != (c = in.read(buffer))) {
            out.write(buffer, 0, c);
        }
    }

    private static void dump(Document doc, OutputStream out) throws TransformerException {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();

        // pretty print
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");

        transformer.transform(new DOMSource(doc), new StreamResult(out));
    }

    private String getXMLThing(String method, String url, String entity, String xpath) throws IOException, GeneralSecurityException, ParserConfigurationException, XPathExpressionException {
        try(ConnectionWrapper ci = makeAPICall(method, url, entity)) {

            int responseCode = ci.getResponseCode();
            if(204 == responseCode
               || 404 == responseCode) {
                return null; // TODO: Something better?
            }

            if(!"application/xml".equals(ci.getContentType())) {
                System.out.println("HTTP response " + ci.getResponseCode());
                dump(ci.getInputStream(), System.err);
                throw new IllegalArgumentException("Expected application/xml, got " + ci.getContentType());
            }

            if(null == xpath) {
                return null;
            } else {
//                System.out.println("Building XML Document...");
                DocumentBuilderFactory df = DocumentBuilderFactory.newInstance();
                DocumentBuilder db = df.newDocumentBuilder();
                Document doc;

                try(InputStream in = ci.getInputStream()) {
                    try {
                        doc = db.parse(in);
//                        System.out.println("Done building XML Document");
//
//                        if(0 > System.currentTimeMillis())
//                        try {
//                            System.out.println(method + ":" + url + " returned document:");
//                            System.out.flush();
//                            dump(doc, System.out);
//                        } catch (TransformerException te) {
//                            te.printStackTrace();
//                        }
                    } catch (SAXException saxe) {
                        throw new IOException("Could not parse XML", saxe);
                    }
                }

                XPathExpression xp = XPathFactory.newInstance().newXPath().compile(xpath);

                return xp.evaluate(doc);
            }
        }
    }

    private int getLocalChannelId(String channelId) throws XPathExpressionException, IOException, GeneralSecurityException, ParserConfigurationException {
        String localChannelId = getXMLThing("POST",
                "/channels/_getSummary?ignoreNewChannels=false",
                "<map></map>",
                "/list/channelSummary[channelId='" + channelId + "']/channelStatus/localChannelId");

        return Integer.parseInt(localChannelId);
    }

    private String getChannelIdByLocalChannelId(int localChannelId) throws XPathExpressionException, IOException, GeneralSecurityException, ParserConfigurationException {
        return getXMLThing("POST",
                "/channels/_getSummary?ignoreNewChannels=false",
                "<map></map>",
                "/list/channelSummary[channelStatus/localChannelId='" + localChannelId + "']/channelId");
    }

    private String getChannelIdByName(String channelName) throws XPathExpressionException, IOException, GeneralSecurityException, ParserConfigurationException {
        return getXMLThing("GET", "/channels/idsAndNames", null, "/map/entry[string[2]='" + channelName + "']/string[1]");
    }

    private String getChannelStatus(String channelId) throws XPathExpressionException, IOException, GeneralSecurityException, ParserConfigurationException {
        return getXMLThing("GET", "/channels/" + channelId + "/status", null, "/dashboardStatus/state");
    }

    public void optimizeChannelTables(String arg) throws XPathExpressionException, IOException, GeneralSecurityException, ParserConfigurationException, SQLException {
        if(arg.matches("\\p{XDigit}{8}-\\p{XDigit}{4}-\\p{XDigit}{4}-\\p{XDigit}{4}-\\p{XDigit}{12}")) {
            // This is a channel id GUID
            System.out.println("Optimizing channel id " + arg);
            optimizeChannelTablesByChannelId(arg);
        } else {
            // Try to parse integer
            try {
                int localChannelId = Integer.parseInt(arg);
                // Probably a local channel id
                System.out.println("Optimizing local channel id " + arg);
                optimizeChannelTablesByLocalChannelId(localChannelId);
            } catch (NumberFormatException nfe) {
                // Probably a channel name

                System.out.println("Optimizing channel name " + arg);
                optimizeChannelTablesByChannelName(arg);
            }
        }
    }

    private void optimizeChannelTablesByChannelId(String channelId) throws XPathExpressionException, IOException, GeneralSecurityException, ParserConfigurationException, SQLException {
        int localChannelId = getLocalChannelId(channelId);

        optimizeChannelTables(channelId, localChannelId);
    }

    private void optimizeChannelTablesByLocalChannelId(int localChannelId) throws XPathExpressionException, IOException, GeneralSecurityException, ParserConfigurationException, SQLException {
        optimizeChannelTables(getChannelIdByLocalChannelId(localChannelId), localChannelId);
    }

    private void optimizeChannelTablesByChannelName(String channelName) throws XPathExpressionException, IOException, GeneralSecurityException, ParserConfigurationException, SQLException {
        String channelId = getChannelIdByName(channelName);
        int localChannelId = getLocalChannelId(channelId);

        optimizeChannelTables(channelId, localChannelId);
    }

    /**
     * Prints the commands you'd need in order to optimize the tables for a channel.
     *
     * @param localChannelId The local channel id.
     *
     * @throws SQLException If the database type can't be determined.
     */
    public static void printOptimizeCommands(int localChannelId, Connection conn) throws SQLException {
        String dbType = getDBType(conn);

        System.out.println("-- Optimizing message metadata for channel " + localChannelId);
        System.out.println(getOptimizeTableCommand("d_m" + localChannelId, dbType));

        System.out.println("-- Optimizing message content for channel " + localChannelId);
        System.out.println(getOptimizeTableCommand("d_mc" + localChannelId, dbType));

        System.out.println("-- Optimizing custom message metadata for channel " + localChannelId);
        System.out.println(getOptimizeTableCommand("d_mcm" + localChannelId, dbType));

        System.out.println("-- Optimizing message delivery information for channel " + localChannelId);
        System.out.println(getOptimizeTableCommand("d_mm" + localChannelId, dbType));

        System.out.println("-- Optimizing message attachments for channel " + localChannelId);
        System.out.println(getOptimizeTableCommand("d_ma" + localChannelId, dbType));

        System.out.println("-- Optimizing message statistics for channel " + localChannelId);
        System.out.println(getOptimizeTableCommand("d_ms" + localChannelId, dbType));
    }

    /**
     * Performs channel optimization.
     *
     * @param channelId The id of the channel.
     * @param localChannelId The local channel id.
     *
     * @throws XPathExpressionException
     * @throws IOException
     * @throws GeneralSecurityException
     * @throws ParserConfigurationException
     * @throws SQLException If there is a problem optimizing the tables.
     */
    private void optimizeChannelTables(String channelId, int localChannelId) throws XPathExpressionException, IOException, GeneralSecurityException, ParserConfigurationException, SQLException  {
        if(null == channelId || "".equals(channelId)) {
            throw new IllegalArgumentException("No channel id specified.");
        }

        boolean restartChannel = true;

        String channelStatus = getChannelStatus(channelId);

        if(null == channelStatus || "STOPPED".equals(channelStatus)) {
            System.out.println("Channel " + channelId + " is not deployed or already stopped. WILL NOT RESTART THIS CHANNEL");

            restartChannel = false;
        }

        long elapsed = System.currentTimeMillis();

        Connection conn = null;
        Statement s = null;

        try {
            if(null == getJDBCUsername()) {
                conn = DriverManager.getConnection(getJDBCURL());
            } else {
                conn = DriverManager.getConnection(getJDBCURL(), getJDBCUsername(), getJDBCPassword());
            }

            if(restartChannel) {
                // Gotta stop it first
                System.out.println("Stopping channel " + channelId);
                getXMLThing("POST", "/channels/" + channelId + "/_stop", null, null);
                System.out.println("Stopped channel " + channelId);
            }

            s = conn.createStatement();

            if(null != getQueryTimeout()) {
                s.setQueryTimeout(getQueryTimeout().intValue());
            }

            try {
                String dbType = getDBType(conn);

                System.out.println("Optimizing message metadata for channel " + localChannelId + "...");
                s.execute(getOptimizeTableCommand("d_m" + localChannelId, dbType));

                System.out.println("Optimizing message content for channel " + localChannelId + "...");
                s.execute(getOptimizeTableCommand("d_mc" + localChannelId, dbType));

                System.out.println("Optimizing custom message metadata for channel " + localChannelId + "...");
                s.execute(getOptimizeTableCommand("d_mcm" + localChannelId, dbType));

                System.out.println("Optimizing message delivery information for channel " + localChannelId + "...");
                s.execute(getOptimizeTableCommand("d_mm" + localChannelId, dbType));

                System.out.println("Optimizing message attachments for channel " + localChannelId + "...");
                s.execute(getOptimizeTableCommand("d_ma" + localChannelId, dbType));

                System.out.println("Optimizing message statistics for channel " + localChannelId + "...");
                s.execute(getOptimizeTableCommand("d_ms" + localChannelId, dbType));
            } catch (SQLException sqle) {
                System.err.println("Caught error during optimization");
                sqle.printStackTrace();
            }
        } finally {
            if(null != s) try { s.close(); } catch (SQLException sqle) {
                System.err.println("Failed to close JDBC statement");
                sqle.printStackTrace();
            }
            if(null != conn) try { conn.close(); } catch (SQLException sqle) {
                System.err.println("Failed to close JDBC connection");
                sqle.printStackTrace();
            }
        }

        if(restartChannel) {
            // Gotta stop it first
            System.out.println("Starting channel " + channelId);
            getXMLThing("POST", "/channels/" + channelId + "/_start", null, null);
            System.out.println("Started channel " + channelId);
        }

        elapsed = System.currentTimeMillis() - elapsed;

        System.out.println("Completed optimization of Mirth channel " + channelId + " in " + prettyPrintMS(elapsed));
    }

    private static String getDBType(Connection conn) throws SQLException {
        DatabaseMetaData dbmd = conn.getMetaData();

        return dbmd.getDatabaseProductName();
    }

    private static String getOptimizeTableCommand(String tableName, String dbType) {
        if("PostgreSQL".equals(dbType)) {
            return "VACUUM FULL " + tableName + ";";
        } else if("MySQL".equals(dbType)
                || "MariaDB".equals(dbType)) {
            // NOTE: Only works with InnoDB tables?
            return "OPTIMIZE TABLE " + tableName + ";"; // TODO NO_WRITE_TO_BINLOG ?
        } else {
            throw new IllegalArgumentException("Not sure how to handle database type '" + dbType + "'");
        }
    }

    private static String prettyPrintMS(long elapsed) {
        if(elapsed < 10 * 1000) {
            return elapsed + "ms";
        } else if(elapsed < 60 * 1000){
            return elapsed / 1000 + "s";
        } else if(elapsed < 60 * 60 * 1000) {
            int sec = (int)elapsed / 1000;
            int min = sec / 60;
            sec %= 60;
            min %= 60;
            return String.format("%d:%02d", min, sec);
        } else {
            int sec = (int)elapsed / 1000;
            int min = sec / 60;
            int hour = min / 60;
            sec %= 60;
            min %= 60;
            return String.format("%d:%02d:%02d", hour, min, sec);
        }
    }
}
