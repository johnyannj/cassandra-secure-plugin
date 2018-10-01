package com.zhaoyanblog.cassandra.client;

import com.datastax.driver.core.AuthProvider;
import com.datastax.driver.core.Authenticator;
import com.datastax.driver.core.exceptions.AuthenticationException;
import com.zhaoyanblog.cassandra.SecureUtils;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

/**
 *  Scram client
 *
 * @author johnyannj
 */
public class ScramAuthProvider implements AuthProvider {

    private String username;
    private String password;

    public ScramAuthProvider(String username, String password) {
        this.username = username;
        this.password = password;
    }

    @Override
    public Authenticator newAuthenticator(InetSocketAddress host, String authenticator) throws AuthenticationException {
        return new ScramAuthenticator(host, username, password);
    }

    protected class ScramAuthenticator implements Authenticator {
        private static final int NONCE_DEFAULT_LENGTH = 24;

        private InetSocketAddress host;
        private final String username;
        private final String password;

        private String clientNonce;

        private String clientFirstMessageBare;
        private byte[] saltedPassword;
        private String authMessage;

        public ScramAuthenticator(InetSocketAddress host, String username, String password) {
            this.username = username;
            this.password = password;
            this.host = host;
        }

        @Override
        public byte[] initialResponse() {

            clientNonce = SecureUtils.gengerateNonce(NONCE_DEFAULT_LENGTH);

            clientFirstMessageBare = "n=" + username + ",r=" + clientNonce;

            String clientFirstMessage = "n,," + clientFirstMessageBare;

            return clientFirstMessage.getBytes(StandardCharsets.UTF_8);
        }

        @Override
        public byte[] evaluateChallenge(byte[] challenge) {

            //process server-first-message;
            String serverFirstMessage = new String(challenge);
            String[] messages = serverFirstMessage.split(",");
            if (messages.length != 3) {

                throw new AuthenticationException(host, "server-first-message is error");
            }
            String nonce = getAttributeValue(messages[0], "r");

            if (nonce == null) {
                throw new AuthenticationException(host, "server-first-message missing attribute r");
            }

            if (!nonce.startsWith(clientNonce) || nonce.length() <= clientNonce.length()) {
                throw new AuthenticationException(host, "server-first-message attribute r missing server nonce");
            }

            String salt = getAttributeValue(messages[1], "s");
            if (salt == null) {
                throw new AuthenticationException(host, "server-first-message missing attribute s");
            }
            String iterations = getAttributeValue(messages[2], "i");
            if (iterations == null) {
                throw new AuthenticationException(host, "server-first-message missing attribute i");
            }

            //prepare client-final-message;
            String clientFinalMessageWithoutProof = "c=biws,r=" + nonce;
            saltedPassword = SecureUtils.pbkdf2(password, SecureUtils.fromBase64(salt), Integer.parseInt(iterations), "HmacSHA256");
            byte[] clientKey = SecureUtils.hmac(saltedPassword, "HmacSHA256", "Client Key");
            byte[] storeKey = SecureUtils.hash(clientKey, "SHA-256");

            authMessage = clientFirstMessageBare + ',' + serverFirstMessage + ',' + clientFinalMessageWithoutProof;
            byte[] clientSignature = SecureUtils.hmac(storeKey, "HmacSHA256", authMessage);
            byte[] clientProof = SecureUtils.xor(clientKey, clientSignature);

            //client-final-message = client-final-message-without-proof "," proof
            String clientFinalMessage = clientFinalMessageWithoutProof + ",p=" + SecureUtils.base64(clientProof);
            return clientFinalMessage.getBytes(StandardCharsets.UTF_8);
        }

        @Override
        public void onAuthenticationSuccess(byte[] token) {

            String serverFinalMessage = new String(token);
            String serverSignatureBase64 = getAttributeValue(serverFinalMessage, "p");
            if (serverSignatureBase64 == null) {
                throw new AuthenticationException(host, "server signature is incorrect");
            }

            //processs sever-final-message
            byte[] serverKey = SecureUtils.hmac(saltedPassword, "HmacSHA256", "Server Key");
            byte[] serverSignature = SecureUtils.hmac(serverKey, "HmacSHA256", authMessage);
            if (!SecureUtils.base64(serverSignature).equals(serverSignatureBase64)) {
                throw new AuthenticationException(host, "server signature is incorrect");
            }
        }

        /**
         * rfc5802#section-8.3
         *
         * Note that the order of attributes in client or server messages is
         *    fixed
         *
         * @param msg "k=v"
         * @param param k
         * @return v
         */
        private String getAttributeValue(String msg, String param) {
            String prefix = param + "=";
            if (msg.startsWith(prefix) && msg.length() > prefix.length()) {
                return msg.substring(prefix.length());
            }
            return null;
        }
    }
}
