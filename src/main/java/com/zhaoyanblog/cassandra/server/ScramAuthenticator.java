package com.zhaoyanblog.cassandra.server;

import com.zhaoyanblog.cassandra.SecureUtils;
import org.apache.cassandra.auth.AuthCache;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.PasswordAuthenticator;
import org.apache.cassandra.exceptions.AuthenticationException;
import org.apache.cassandra.exceptions.RequestExecutionException;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Field;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ExecutionException;


public class ScramAuthenticator extends PasswordAuthenticator {

    private AuthCache<String, String> authCacheProxy;

    @Override
    public SaslNegotiator newSaslNegotiator(InetAddress clientAddress) {
        return new ScramSaslAuthenticator();
    }

    @Override
    @SuppressWarnings("unchecked")
    public void setup() {
        super.setup();
        try {
            Field field = PasswordAuthenticator.class.getDeclaredField("cache");
            field.setAccessible(true);
            this.authCacheProxy = (AuthCache) field.get(this);
        }
        catch (NoSuchFieldException | IllegalAccessException e) {
            throw new IllegalStateException("current Cassandra version not supported.", e);
        }
    }

    @Override
    public AuthenticatedUser legacyAuthenticate(Map<String, String> credentials) throws AuthenticationException {
        return null;
    }

    private UserSecureInfo getUserSecureInfo(String username) {
        String storeHash;
        try {
            storeHash = authCacheProxy.get(username);
        }
        catch (ExecutionException e) {
            // an unanticipated exception occured whilst querying the credentials table
            if (e.getCause() instanceof RequestExecutionException) {
                throw new AuthenticationException(String.format("Error during authentication of user %s : %s", username, e.getMessage()));
            }
            throw new AuthenticationException(String.format("Error during authentication of user %s : %s", username, e.getMessage()));
        }
        if (storeHash == null) {
            throw new AuthenticationException("client-first-message is error.");
        }
        return new UserSecureInfo(storeHash);
    }

    private class UserSecureInfo {
        private String salt;
        private String iteration;
        private String serverKey;
        private String storeKey;

        UserSecureInfo(String storeHash) {
            String[] splits = storeHash.split(",");
            salt = splits[0];
            iteration = splits[1];
            serverKey = splits[2];
            storeKey = splits[3];
        }
    }

    private class ScramSaslAuthenticator implements SaslNegotiator {
        private static final int NONCE_DEFAULT_LENGTH = 24;
        private boolean complete = false;
        private String username;
        private UserSecureInfo userSecureInfo = null;
        private String clientNonce;
        private String serverNonce;
        private String serverFirstMessage;
        private String clientFirstMessageBare;

        @Override
        public byte[] evaluateResponse(byte[] clientResponse) throws AuthenticationException {
            String msg = new String(clientResponse);

            if (serverFirstMessage == null) {
                if (!msg.startsWith("n,,n=")) {
                    throw new AuthenticationException("client-first-message is error.");
                }
                String[] messages = msg.split(",");
                if (messages.length != 4) {
                    throw new AuthenticationException("client-first-message is error.");
                }
                username = getAttributeValue(messages[2], "n");
                if (StringUtils.isEmpty(username)) {
                    throw new AuthenticationException("client-first-message is error.");
                }
                clientNonce = getAttributeValue(messages[3], "r");
                if (StringUtils.isEmpty(clientNonce)) {
                    throw new AuthenticationException("client-first-message is error.");
                }
                userSecureInfo = getUserSecureInfo(username);
                serverNonce = SecureUtils.gengerateNonce(NONCE_DEFAULT_LENGTH);
                clientFirstMessageBare = "n=" + username + ",r=" + clientNonce;
                serverFirstMessage = "r=" + clientNonce + serverNonce +
                        ",s=" + userSecureInfo.salt +
                        ",i=" + userSecureInfo.iteration;
                return serverFirstMessage.getBytes(StandardCharsets.UTF_8);
            }
            else {
                String[] messages = msg.split(",");
                if (messages.length != 3) {
                    throw new AuthenticationException("client-first-message is error.");
                }
                String gs2Header = getAttributeValue(messages[0], "c");
                if (!"biws".equals(gs2Header)) {
                    throw new AuthenticationException("client-final-message is error.");
                }
                String clientAndServerNonce = getAttributeValue(messages[1], "r");
                if (!(clientNonce + serverNonce).equals(clientAndServerNonce)) {
                    throw new AuthenticationException("client-final-message is error.");
                }
                String clientProof = getAttributeValue(messages[2], "p");
                if (clientProof == null) {
                    throw new AuthenticationException("client-final-message is error.");
                }
                String clientFinalMessageWithoutProof = "c=biws,r=" + clientAndServerNonce;
                String authMessage = clientFirstMessageBare + ',' + serverFirstMessage + ',' + clientFinalMessageWithoutProof;
                byte[] clientSignature = SecureUtils.hmac(userSecureInfo.storeKey, "HmacSHA256", authMessage);
                byte[] clientKey = SecureUtils.xor(SecureUtils.fromBase64(clientProof), clientSignature);
                byte[] storeKey = SecureUtils.hash(clientKey, "SHA-256");
                if (!userSecureInfo.storeKey.equals(SecureUtils.base64(storeKey))) {
                    LoggerFactory.getLogger("").error("1----");
                    throw new AuthenticationException("client-final-message is error.");
                }
                complete = true;
                byte[] serverSign = SecureUtils.hmac(SecureUtils.fromBase64(userSecureInfo.serverKey), "HmacSHA256", authMessage);
                String serverFinalMessage = "p=" + SecureUtils.base64(serverSign);
                return serverFinalMessage.getBytes(StandardCharsets.UTF_8);
            }
        }

        @Override
        public boolean isComplete() {
            return complete;
        }

        @Override
        public AuthenticatedUser getAuthenticatedUser() throws AuthenticationException {
            if (!complete) {
                throw new AuthenticationException("SASL negotiation not complete");
            }
            return new AuthenticatedUser(username);
        }

        /**
         * rfc5802#section-8.3
         * <p>
         * Note that the order of attributes in client or server messages is
         * fixed
         *
         * @param msg   "k=v"
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
