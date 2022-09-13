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
package net.christopherschultz.util;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Utilities for TLS.
 *
 * @author Christopher Schultz
 */
public class TLSUtils {
    /**
     * A set of TrustManagers that simply trusts <i>all</i> certificates.
     */
    private static final TrustManager[] trustAllCerts = new TrustManager[] {
            new TrustAllTrustManager() };

    /**
     * Returns a set of TrustManagers that trusts all certificates.
     *
     * <b>WARNING:</b> using this TrustManager disabled important certificate
     * checks and shouldn't be used in a production system.
     *
     * @return An array of TrustManagers that will trust all certificates.
     */
    public static TrustManager[] getTrustAllCertsTrustManagers()
    {
        return trustAllCerts.clone();
    }

    /**
     * A TrustManager that trusts <i>all</i> certificates.
     */
    private static class TrustAllTrustManager implements X509TrustManager {
        private static final X509Certificate[] NONE = new X509Certificate[0];

        public TrustAllTrustManager()
        {
        }

        public X509Certificate[] getAcceptedIssuers()
        {
            return NONE;
        }

        public void checkClientTrusted(X509Certificate[] certs,
                                       String authType)
        {
            // Trust all clients
        }

        public void checkServerTrusted(X509Certificate[] certs,
                                       String authType)
        {
            // Trust all servers
        }
    }

    /**
     * Creates an SSLSocketFactory that supports only the specified protocols
     * and ciphers, along with a set of KeyManagers.
     *
     * @param provider The (optional) crypto provider to provide crypto
     *        services. Default = JVM default provider.
     * @param protocol The TLS protocol to use. Probably <code>TLS</code>.
     * @param sslEnabledProtocols An array of protocol names to actually
     *        enable, e.g. <code>SSLv2Hello</code>, <code>TLSv1.1</code>, etc.
     *        If <code>null</code>, allow all protocols enabled by default
     *        by the JVM.
     * @param sslCipherSuites An array of cipher suite names from Java's
     *        cryptographic names reference. If <code>null</code>, allow
     *        all cipher suites enabled by default by the JVM.
     * @param kms An array of KeyManagers to provide client keys to servers
     *        that request them.
     * @param random The (optional) SecureRandom object to use.
     * @param tms An array of TrustManagers to provide certificate trust.
     *
     * @return An SSLSocketFactory configured with the requested constraints.
     *
     * @throws NoSuchAlgorithmException If the protocol is not supported by
     *         the requested provider.
     * @throws KeyManagementException If there is a problem initializing the
     *         SSLContext.
     */
    public static SSLSocketFactory getSSLSocketFactory(Provider provider, String protocol, String[] sslEnabledProtocols,
            String[] sslCipherSuites, KeyManager[] kms, TrustManager[] tms, SecureRandom random)
            throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext sc;
        if (null != provider) {
            sc = SSLContext.getInstance(protocol, provider);
        } else {
            sc = SSLContext.getInstance(protocol);
        }

        sc.init(kms, tms, random);
        SSLSocketFactory sf = sc.getSocketFactory();
        if (null != sslEnabledProtocols || null != sslCipherSuites) {
            sf = new CustomSSLSocketFactory((SSLSocketFactory) sf, sslEnabledProtocols, sslCipherSuites);
        }

        return (SSLSocketFactory) sf;
    }

    /**
     * In order to customize the specific enabled protocols and cipher suites,
     * a customized SSLSocketFactory must be used.
     *
     * This is just a wrapper around that customization.
     */
    public static class CustomSSLSocketFactory
        extends javax.net.ssl.SSLSocketFactory
    {
        private final String[] _sslEnabledProtocols;
        private final String[] _sslCipherSuites;
        private final SSLSocketFactory _base;

        public CustomSSLSocketFactory(SSLSocketFactory base,
                                      String[] sslEnabledProtocols,
                                      String[] sslCipherSuites)
        {
            _base = base;
            if(null == sslEnabledProtocols)
                _sslEnabledProtocols = null;
            else
                _sslEnabledProtocols = sslEnabledProtocols.clone();
            if(null == sslCipherSuites || 0 == sslCipherSuites.length)
                _sslCipherSuites = getDefaultCipherSuites();
            else if(1 == sslCipherSuites.length
                    && "ALL".equalsIgnoreCase(sslCipherSuites[0]))
                _sslCipherSuites = getSupportedCipherSuites();
            else
                _sslCipherSuites = sslCipherSuites.clone();
        }

        public final String[] getDefaultCipherSuites()
        {
            return _base.getDefaultCipherSuites();
        }

        public final String[] getSupportedCipherSuites()
        {
            return _base.getSupportedCipherSuites();
        }

        private SSLSocket customize(Socket s)
        {
            if(!(s instanceof SSLSocket))
                throw new IllegalArgumentException(
                        "Tried to customize a non-SSL socket");

            SSLSocket socket = (SSLSocket) s;

            if(null != _sslEnabledProtocols)
                socket.setEnabledProtocols(_sslEnabledProtocols);

            socket.setEnabledCipherSuites(_sslCipherSuites);

            return socket;
        }

        @Override
        public Socket createSocket(Socket s, String host, int port,
                                   boolean autoClose)
            throws IOException
        {
            return customize(_base.createSocket(s, host, port, autoClose));
        }

        @Override
        public Socket createSocket(String host, int port)
            throws IOException
        {
            return customize(_base.createSocket(host, port));
        }

        @Override
        public Socket createSocket(InetAddress host, int port)
            throws IOException
        {
            return customize(_base.createSocket(host, port));
        }

        @Override
        public Socket createSocket(String host, int port, InetAddress localHost,
                                   int localPort)
            throws IOException
        {
            return customize(_base.createSocket(host, port, localHost,
                                                localPort));
        }

        @Override
        public Socket createSocket(InetAddress address, int port,
                                   InetAddress localAddress, int localPort)
            throws IOException
        {
            return customize(_base.createSocket(address, port, localAddress,
                                                localPort));
        }
    }

    /**
     * In order to customize the specific enabled protocols and cipher suites,
     * a customized SSLSocketFactory must be used.
     *
     * This is just a wrapper around that customization.
     */
    public static class CustomSSLServerSocketFactory
        extends javax.net.ssl.SSLServerSocketFactory
    {
        private final String[] _sslEnabledProtocols;
        private final String[] _sslCipherSuites;
        private final SSLServerSocketFactory _base;

        public CustomSSLServerSocketFactory(SSLServerSocketFactory base,
                                            String[] sslEnabledProtocols,
                                            String[] sslCipherSuites)
        {
            _base = base;
            if(null == sslEnabledProtocols)
                _sslEnabledProtocols = null;
            else
                _sslEnabledProtocols = sslEnabledProtocols.clone();
            if(null == sslCipherSuites || 0 == sslCipherSuites.length)
                _sslCipherSuites = getDefaultCipherSuites();
            else if(1 == sslCipherSuites.length
                    && "ALL".equalsIgnoreCase(sslCipherSuites[0]))
                _sslCipherSuites = getSupportedCipherSuites();
            else
                _sslCipherSuites = sslCipherSuites.clone();
        }

        public final String[] getDefaultCipherSuites()
        {
            return _base.getDefaultCipherSuites();
        }

        public final String[] getSupportedCipherSuites()
        {
            return _base.getSupportedCipherSuites();
        }

        private SSLServerSocket customize(ServerSocket s)
        {
            if(!(s instanceof SSLServerSocket))
                throw new IllegalArgumentException(
                        "Tried to customize a non-SSL server socket");

            SSLServerSocket socket = (SSLServerSocket) s;

            if(null != _sslEnabledProtocols)
                socket.setEnabledProtocols(_sslEnabledProtocols);

            socket.setEnabledCipherSuites(_sslCipherSuites);

            return socket;
        }

        @Override
        public SSLServerSocket createServerSocket()
            throws IOException
        {
            return customize(_base.createServerSocket());
        }

        @Override
        public SSLServerSocket createServerSocket(int port)
            throws IOException
        {
            return customize(_base.createServerSocket(port));
        }

        @Override
        public SSLServerSocket createServerSocket(int port, int backlog)
            throws IOException
        {
            return customize(_base.createServerSocket(port, backlog));
        }

        @Override
        public SSLServerSocket createServerSocket(int port, int backlog,
                                                  InetAddress ifAddress)
            throws IOException
        {
            return customize(_base.createServerSocket(port, backlog,
                                                      ifAddress));
        }
    }
}
