/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.tomcat.util.net.openssl.panama;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.invoke.MethodHandle;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;

import org.apache.catalina.core.OpenSSLLifecycleListener;
import org.apache.tomcat.util.compat.JreCompat;
import org.apache.tomcat.util.net.TesterSupport;

/**
 * Checks the error recorded by the OpenSSL FFM engine when an OCSP request does
 * not produce a usable response. Only a responder that is unavailable (network
 * error, timeout, HTTP error, OCSP status internalError or tryLater) may be
 * reported as X509_V_ERR_UNABLE_TO_GET_CRL, which is the only error that is
 * allowed to soft-fail. Every other failure must be reported with an error that
 * causes the certificate verification to hard-fail.
 * <p>
 * The test sources are compiled for Java 8 so all access to the FFM API and to
 * the FFM based classes is via reflection.
 */
public class TestOpenSSLEngineOcspInternalError {

    // Constants from OpenSSL's x509_vfy.h and ocsp.h
    private static final int X509_V_OK = 0;
    private static final int X509_V_ERR_UNABLE_TO_GET_CRL = 3;
    private static final int X509_V_ERR_APPLICATION_VERIFICATION = 50;
    private static final int V_OCSP_CERTSTATUS_UNKNOWN = 2;

    // DER encoded OCSPResponse with only a responseStatus (RFC 6960)
    private static final byte[] OCSP_MALFORMED_REQUEST = { 0x30, 0x03, 0x0a, 0x01, 0x01 };
    private static final byte[] OCSP_INTERNAL_ERROR = { 0x30, 0x03, 0x0a, 0x01, 0x02 };
    private static final byte[] OCSP_TRY_LATER = { 0x30, 0x03, 0x0a, 0x01, 0x03 };
    private static final byte[] OCSP_UNAUTHORIZED = { 0x30, 0x03, 0x0a, 0x01, 0x06 };

    // Larger than the maximum OCSP response size accepted by OpenSSLEngine (64KiB)
    private static final int OVERSIZED_RESPONSE_LENGTH = 200 * 1024;

    private static final int OCSP_TIMEOUT = 15000;
    private static final int OCSP_SHORT_TIMEOUT = 1000;

    private static final String OPENSSL_H = "org.apache.tomcat.util.openssl.openssl_h";
    private static final String ENGINE = "org.apache.tomcat.util.net.openssl.panama.OpenSSLEngine";

    private static final String HOST = "127.0.0.1";

    private static Class<?> memorySegmentClass;
    private static Class<?> arenaClass;
    private static Class<?> opensslH;
    private static Object nullSegment;
    private static Object addressLayout;
    private static Object byteLayout;
    private static Object classArena;

    private static MethodHandle x509StoreCtxNew;
    private static MethodHandle x509StoreCtxFree;

    private static Object leaf;
    private static Object issuer;

    private Object sslCtx;
    private Object engineState;
    private Object x509ctx;
    private Responder responder;


    @BeforeClass
    public static void setUp() throws Exception {
        Assume.assumeTrue("FFM requires Java 22 or later", JreCompat.isJre22Available());
        @SuppressWarnings("unused")
        OpenSSLLifecycleListener listener = new OpenSSLLifecycleListener();
        Assume.assumeTrue("OpenSSL is not available", OpenSSLLifecycleListener.isAvailable());

        memorySegmentClass = Class.forName("java.lang.foreign.MemorySegment");
        arenaClass = Class.forName("java.lang.foreign.Arena");
        opensslH = Class.forName(OPENSSL_H);
        nullSegment = memorySegmentClass.getField("NULL").get(null);
        Class<?> valueLayoutClass = Class.forName("java.lang.foreign.ValueLayout");
        addressLayout = valueLayoutClass.getField("ADDRESS").get(null);
        byteLayout = valueLayoutClass.getField("JAVA_BYTE").get(null);
        classArena = arenaClass.getMethod("ofAuto").invoke(null);

        // Functions not exposed by openssl_h
        x509StoreCtxNew = downcall("X509_STORE_CTX_new", addressLayout);
        x509StoreCtxFree = downcall("X509_STORE_CTX_free", null, addressLayout);

        // Client certificate and its issuer
        KeyStore ks = KeyStore.getInstance("JKS");
        try (InputStream is = new FileInputStream(new File(TesterSupport.CLIENT_JKS))) {
            ks.load(is, TesterSupport.JKS_PASS.toCharArray());
        }
        Certificate[] chain = ks.getCertificateChain(TesterSupport.CLIENT_ALIAS);
        Assert.assertNotNull(chain);
        Assert.assertEquals(2, chain.length);
        leaf = toNativeX509(chain[0]);
        issuer = toNativeX509(chain[1]);
    }


    @AfterClass
    public static void tearDown() throws Exception {
        if (leaf != null) {
            call("X509_free", leaf);
            leaf = null;
        }
        if (issuer != null) {
            call("X509_free", issuer);
            issuer = null;
        }
    }


    @After
    public void releaseVerificationContext() throws Throwable {
        if (responder != null) {
            responder.close();
            responder = null;
        }
        if (engineState != null) {
            // Frees the SSL and the BIO
            ((Runnable) engineState).run();
            engineState = null;
        }
        if (sslCtx != null) {
            call("SSL_CTX_free", sslCtx);
            sslCtx = null;
        }
        if (x509ctx != null) {
            x509StoreCtxFree.invokeWithArguments(x509ctx);
            x509ctx = null;
        }
    }


    @Test
    public void testResponderHttpError() throws Throwable {
        // Responder is not available - soft-failable
        responder = new Responder(500, new byte[0], true);
        doTestOcspFailure(responder.getUrl(), OCSP_TIMEOUT, X509_V_ERR_UNABLE_TO_GET_CRL);
        Assert.assertTrue(responder.getRequestCount() > 0);
    }


    @Test
    public void testResponderConnectionRefused() throws Throwable {
        int port;
        try (ServerSocket s = new ServerSocket()) {
            s.bind(new InetSocketAddress(HOST, 0));
            port = s.getLocalPort();
        }
        // Nothing is listening on the port anymore - soft-failable
        doTestOcspFailure(new URL("http", HOST, port, "/ocsp"), OCSP_TIMEOUT, X509_V_ERR_UNABLE_TO_GET_CRL);
    }


    @Test
    public void testResponderReadTimeout() throws Throwable {
        // Responder accepts the request but never answers - soft-failable
        responder = new Responder(200, OCSP_INTERNAL_ERROR, false);
        doTestOcspFailure(responder.getUrl(), OCSP_SHORT_TIMEOUT, X509_V_ERR_UNABLE_TO_GET_CRL);
        Assert.assertTrue(responder.getRequestCount() > 0);
    }


    @Test
    public void testResponderResponseTooLarge() throws Throwable {
        // Responder sends more data than any OCSP response could need - not soft-failable
        responder = new Responder(200, new byte[OVERSIZED_RESPONSE_LENGTH], true);
        int expected = ((Integer) call("X509_V_ERR_OCSP_RESP_INVALID")).intValue();
        Assert.assertNotEquals(X509_V_ERR_UNABLE_TO_GET_CRL, expected);
        doTestOcspFailure(responder.getUrl(), OCSP_TIMEOUT, expected);
        Assert.assertTrue(responder.getRequestCount() > 0);
    }


    @Test
    public void testResponseStatusInternalError() throws Throwable {
        // OCSP responseStatus internalError(2) - soft-failable, consistent with JSSE
        responder = new Responder(200, OCSP_INTERNAL_ERROR, true);
        doTestOcspFailure(responder.getUrl(), OCSP_TIMEOUT, X509_V_ERR_UNABLE_TO_GET_CRL);
        Assert.assertTrue(responder.getRequestCount() > 0);
    }


    @Test
    public void testResponseStatusTryLater() throws Throwable {
        // OCSP responseStatus tryLater(3) - soft-failable, consistent with JSSE
        responder = new Responder(200, OCSP_TRY_LATER, true);
        doTestOcspFailure(responder.getUrl(), OCSP_TIMEOUT, X509_V_ERR_UNABLE_TO_GET_CRL);
        Assert.assertTrue(responder.getRequestCount() > 0);
    }


    @Test
    public void testResponseStatusMalformedRequest() throws Throwable {
        // OCSP responseStatus malformedRequest(1) - not soft-failable
        responder = new Responder(200, OCSP_MALFORMED_REQUEST, true);
        doTestOcspFailure(responder.getUrl(), OCSP_TIMEOUT, X509_V_ERR_APPLICATION_VERIFICATION);
        Assert.assertTrue(responder.getRequestCount() > 0);
    }


    @Test
    public void testResponseStatusUnauthorized() throws Throwable {
        // OCSP responseStatus unauthorized(6) - not soft-failable
        responder = new Responder(200, OCSP_UNAUTHORIZED, true);
        doTestOcspFailure(responder.getUrl(), OCSP_TIMEOUT, X509_V_ERR_APPLICATION_VERIFICATION);
        Assert.assertTrue(responder.getRequestCount() > 0);
    }


    @Test
    public void testResponderInvalidResponse() throws Throwable {
        // Not an OCSP response at all - not soft-failable
        responder = new Responder(200, "This is not an OCSP response".getBytes(StandardCharsets.ISO_8859_1), true);
        doTestOcspFailure(responder.getUrl(), OCSP_TIMEOUT, X509_V_ERR_APPLICATION_VERIFICATION);
        Assert.assertTrue(responder.getRequestCount() > 0);
    }


    private void doTestOcspFailure(URL url, int ocspTimeout, int expectedError) throws Throwable {
        createVerificationContext(ocspTimeout);
        Assert.assertEquals(X509_V_OK, getError());

        Assert.assertEquals(V_OCSP_CERTSTATUS_UNKNOWN, processOCSPRequest(url));
        Assert.assertEquals(expectedError, getError());
    }


    private void createVerificationContext(int ocspTimeout) throws Throwable {
        x509ctx = x509StoreCtxNew.invokeWithArguments();
        Assert.assertNotEquals(nullSegment, x509ctx);

        sslCtx = call("SSL_CTX_new", call("TLS_server_method"));
        Assert.assertNotEquals(nullSegment, sslCtx);
        Object ssl = call("SSL_new", sslCtx);
        Assert.assertNotEquals(nullSegment, ssl);
        Object networkBIO = call("BIO_new", call("BIO_s_mem"));
        Assert.assertNotEquals(nullSegment, networkBIO);

        Class<?> engineStateClass = Class.forName(ENGINE + "$EngineState");
        Constructor<?> constructor = engineStateClass.getDeclaredConstructor(memorySegmentClass,
                memorySegmentClass, int.class, boolean.class, int.class, int.class);
        constructor.setAccessible(true);
        engineState = constructor.newInstance(ssl, networkBIO, Integer.valueOf(10), Boolean.FALSE,
                Integer.valueOf(ocspTimeout), Integer.valueOf(0));
    }


    private int processOCSPRequest(URL url) throws Exception {
        Class<?> engineStateClass = Class.forName(ENGINE + "$EngineState");
        Method processOCSPRequest = Class.forName(ENGINE).getDeclaredMethod("processOCSPRequest",
                engineStateClass, URL.class, memorySegmentClass, memorySegmentClass, memorySegmentClass, arenaClass);
        processOCSPRequest.setAccessible(true);
        Object localArena = arenaClass.getMethod("ofConfined").invoke(null);
        try {
            return ((Integer) processOCSPRequest.invoke(null, engineState, url, issuer, leaf, x509ctx, localArena))
                    .intValue();
        } finally {
            ((AutoCloseable) localArena).close();
        }
    }


    private int getError() throws Exception {
        return ((Integer) call("X509_STORE_CTX_get_error", x509ctx)).intValue();
    }


    private static Object toNativeX509(Certificate certificate) throws Exception {
        byte[] der = certificate.getEncoded();
        Object derSegment = arenaClass.getMethod("allocateFrom",
                Class.forName("java.lang.foreign.ValueLayout$OfByte"), byte[].class)
                .invoke(classArena, byteLayout, der);
        Object derPointer = arenaClass.getMethod("allocateFrom",
                Class.forName("java.lang.foreign.AddressLayout"), memorySegmentClass)
                .invoke(classArena, addressLayout, derSegment);
        Object x509 = call("d2i_X509", nullSegment, derPointer, Long.valueOf(der.length));
        Assert.assertNotEquals(nullSegment, x509);
        return x509;
    }


    private static Object call(String name, Object... args) throws Exception {
        for (Method method : opensslH.getMethods()) {
            if (method.getName().equals(name) && method.getParameterCount() == args.length) {
                return method.invoke(null, args);
            }
        }
        throw new NoSuchMethodException(name);
    }


    private static MethodHandle downcall(String symbol, Object returnLayout, Object... argumentLayouts)
            throws Exception {
        Class<?> memoryLayoutClass = Class.forName("java.lang.foreign.MemoryLayout");
        Class<?> functionDescriptorClass = Class.forName("java.lang.foreign.FunctionDescriptor");
        Class<?> linkerClass = Class.forName("java.lang.foreign.Linker");
        Class<?> linkerOptionClass = Class.forName("java.lang.foreign.Linker$Option");

        Object layouts = Array.newInstance(memoryLayoutClass, argumentLayouts.length);
        for (int i = 0; i < argumentLayouts.length; i++) {
            Array.set(layouts, i, argumentLayouts[i]);
        }
        Object descriptor;
        if (returnLayout == null) {
            descriptor = functionDescriptorClass.getMethod("ofVoid", layouts.getClass()).invoke(null, layouts);
        } else {
            descriptor = functionDescriptorClass.getMethod("of", memoryLayoutClass, layouts.getClass())
                    .invoke(null, returnLayout, layouts);
        }

        Method findOrThrow = opensslH.getDeclaredMethod("findOrThrow", String.class);
        findOrThrow.setAccessible(true);
        Object address = findOrThrow.invoke(null, symbol);

        Object linker = linkerClass.getMethod("nativeLinker").invoke(null);
        Object options = Array.newInstance(linkerOptionClass, 0);
        return (MethodHandle) linkerClass.getMethod("downcallHandle", memorySegmentClass, functionDescriptorClass,
                options.getClass()).invoke(linker, address, descriptor, options);
    }


    /**
     * Minimal HTTP/1.1 OCSP responder that reads one request per connection and
     * then either sends a fixed response or never answers.
     */
    private static final class Responder implements Runnable {

        private final ServerSocket serverSocket;
        private final int status;
        private final byte[] body;
        private final boolean answer;
        private final List<Socket> sockets = new ArrayList<>();
        private final AtomicInteger requestCount = new AtomicInteger();
        private final Thread thread;
        private volatile boolean closed = false;

        Responder(int status, byte[] body, boolean answer) throws IOException {
            this.status = status;
            this.body = body;
            this.answer = answer;
            serverSocket = new ServerSocket();
            serverSocket.bind(new InetSocketAddress(HOST, 0));
            thread = new Thread(this, "TestOcspResponder");
            thread.setDaemon(true);
            thread.start();
        }

        URL getUrl() throws IOException {
            return new URL("http", HOST, serverSocket.getLocalPort(), "/ocsp");
        }

        int getRequestCount() {
            return requestCount.get();
        }

        @Override
        public void run() {
            while (!closed) {
                Socket socket;
                try {
                    socket = serverSocket.accept();
                } catch (IOException ioe) {
                    // Server socket closed
                    return;
                }
                synchronized (sockets) {
                    sockets.add(socket);
                }
                handle(socket);
            }
        }

        private void handle(Socket socket) {
            try {
                InputStream is = socket.getInputStream();
                int contentLength = readRequestHead(is);
                for (int i = 0; i < contentLength; i++) {
                    if (is.read() == -1) {
                        break;
                    }
                }
                requestCount.incrementAndGet();
                if (!answer) {
                    // Leave the connection open without ever answering
                    return;
                }
                OutputStream os = socket.getOutputStream();
                String head = "HTTP/1.1 " + status + " Status\r\n" +
                        "Content-Type: application/ocsp-response\r\n" +
                        "Content-Length: " + body.length + "\r\n" +
                        "Connection: close\r\n\r\n";
                os.write(head.getBytes(StandardCharsets.ISO_8859_1));
                os.write(body);
                os.flush();
                socket.close();
            } catch (IOException ioe) {
                // The client may stop reading the response early
            }
        }

        private static int readRequestHead(InputStream is) throws IOException {
            ByteArrayOutputStream head = new ByteArrayOutputStream();
            byte[] end = { '\r', '\n', '\r', '\n' };
            int matched = 0;
            int b;
            while (matched < end.length && (b = is.read()) != -1) {
                head.write(b);
                if (b == end[matched]) {
                    matched++;
                } else {
                    matched = (b == '\r') ? 1 : 0;
                }
            }
            int contentLength = 0;
            String[] lines = new String(head.toByteArray(), StandardCharsets.ISO_8859_1).split("\r\n");
            for (String line : lines) {
                if (line.toLowerCase(Locale.ENGLISH).startsWith("content-length:")) {
                    contentLength = Integer.parseInt(line.substring("content-length:".length()).trim());
                }
            }
            return contentLength;
        }

        void close() throws InterruptedException {
            closed = true;
            try {
                serverSocket.close();
            } catch (IOException ioe) {
                // Ignore
            }
            synchronized (sockets) {
                for (Socket socket : sockets) {
                    try {
                        socket.close();
                    } catch (IOException ioe) {
                        // Ignore
                    }
                }
                sockets.clear();
            }
            thread.join(5000);
        }
    }
}
