package com.zhaoyanblog.cassandra.server;

import com.google.common.base.Joiner;
import com.google.common.base.Predicates;
import com.google.common.base.Strings;
import com.google.common.collect.Iterables;
import com.zhaoyanblog.cassandra.SecureUtils;
import org.apache.cassandra.auth.*;
import org.apache.cassandra.config.SchemaConstants;
import org.apache.cassandra.cql3.CQLStatement;
import org.apache.cassandra.cql3.QueryProcessor;
import org.apache.cassandra.exceptions.RequestExecutionException;
import org.apache.cassandra.exceptions.RequestValidationException;
import org.apache.cassandra.service.ClientState;
import org.apache.cassandra.service.StorageService;
import org.apache.commons.lang3.StringUtils;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.Callable;

public class ScramRoleManager extends CassandraRoleManager {

    static final String DEFAULT_SUPERUSER_NAME = "cassandra";
    static final String DEFAULT_SUPERUSER_PASSWORD = "cassandra";

    @Override
    public void setup() {
        CQLStatement statement = QueryProcessor.parseStatement(String.format("SELECT * from %s.%s WHERE role = ?",
                SchemaConstants.AUTH_KEYSPACE_NAME,
                AuthKeyspace.ROLES)).prepare(ClientState.forInternalCalls()).statement;
        try {
            Field loadRoleStatementField = CassandraRoleManager.class.getDeclaredField("loadRoleStatement");
            loadRoleStatementField.setAccessible(true);
            loadRoleStatementField.set(this, statement);

            Method scheduleSetupTaskMethod = CassandraRoleManager.class.getDeclaredMethod("scheduleSetupTask", Callable.class);
            scheduleSetupTaskMethod.setAccessible(true);
            scheduleSetupTaskMethod.invoke(this, (Callable<Void>) () -> {
                setupDefaultRole();
                return null;
            });
        }
        catch (NoSuchFieldException | NoSuchMethodException | IllegalAccessException e) {
            e.printStackTrace();
            throw new IllegalStateException("current Cassandra version not supported.", e);
        }
        catch (InvocationTargetException e) {
            e.printStackTrace();
            throw new IllegalStateException("init default user failed.", e.getCause());
        }
    }

    @Override
    public void createRole(AuthenticatedUser performer, RoleResource role, RoleOptions options) throws RequestValidationException, RequestExecutionException {
        if (options.getPassword().isPresent()) {
            String insertCql = String.format("INSERT INTO %s.%s (role, is_superuser, can_login, salted_hash) VALUES ('%s', %s, %s, '%s')",
                    SchemaConstants.AUTH_KEYSPACE_NAME,
                    AuthKeyspace.ROLES,
                    escape(role.getRoleName()),
                    options.getSuperuser().or(false),
                    options.getLogin().or(false),
                    escape(hashpw(options.getPassword().get())));
            QueryProcessor.process(insertCql, consistencyForRole(role.getRoleName()));
        }
        else {
            super.createRole(performer, role, options);
        }
    }

    @Override
    public void alterRole(AuthenticatedUser performer, RoleResource role, RoleOptions options) {
        String assignments = Joiner.on(',').join(Iterables.filter(optionsToAssignments(options.getOptions()),
                Predicates.notNull()));
        if (!Strings.isNullOrEmpty(assignments)) {
            QueryProcessor.process(String.format("UPDATE %s.%s SET %s WHERE role = '%s'",
                    SchemaConstants.AUTH_KEYSPACE_NAME,
                    AuthKeyspace.ROLES,
                    assignments,
                    escape(role.getRoleName())),
                    consistencyForRole(role.getRoleName()));
        }
    }

    private Iterable<String> optionsToAssignments(Map<Option, Object> options) {
        return Iterables.transform(
                options.entrySet(),
                entry -> {
                    switch (entry.getKey()) {
                        case LOGIN:
                            return String.format("can_login = %s", entry.getValue());
                        case SUPERUSER:
                            return String.format("is_superuser = %s", entry.getValue());
                        case PASSWORD:
                            return String.format("salted_hash = '%s'", escape(hashpw((String) entry.getValue())));
                        default:
                            return null;
                    }
                });
    }

    private static void setupDefaultRole() {
        if (StorageService.instance.getTokenMetadata().sortedTokens().isEmpty()) {
            throw new IllegalStateException("CassandraRoleManager skipped default role setup: no known tokens in ring");
        }

        try {
            Method hasExistingRoles = CassandraRoleManager.class.getDeclaredMethod("hasExistingRoles", null);
            hasExistingRoles.setAccessible(true);
            if (!(Boolean) hasExistingRoles.invoke(null, null)) {
                QueryProcessor.process(String.format("INSERT INTO %s.%s (role, is_superuser, can_login, salted_hash) " +
                                "VALUES ('%s', true, true, '%s')",
                        SchemaConstants.AUTH_KEYSPACE_NAME,
                        AuthKeyspace.ROLES,
                        DEFAULT_SUPERUSER_NAME,
                        hashpw(DEFAULT_SUPERUSER_PASSWORD)
                        ),
                        consistencyForRole(DEFAULT_SUPERUSER_NAME));
            }
        }
        catch (ReflectiveOperationException e) {
            throw new IllegalStateException("current Cassandra version not supported.", e);
        }
    }

    private static String hashpw(String password) {

        int iterations = 4096;
        byte[] salt = new byte[24];
        new SecureRandom().nextBytes(salt);
        byte[] saltedPassword = SecureUtils.pbkdf2(password, salt, iterations, "HmacSHA256");
        byte[] clientKey = SecureUtils.hmac(saltedPassword, "HmacSHA256", "Client Key");
        byte[] serverKey = SecureUtils.hmac(saltedPassword, "HmacSHA256", "Server Key");
        byte[] storeKey = SecureUtils.hash(clientKey, "SHA-256");
        return StringUtils.join(new Object[]{SecureUtils.base64(salt),
                iterations,
                SecureUtils.base64(serverKey),
                SecureUtils.base64(storeKey)}, ",");
    }

    private static String escape(String name) {
        return StringUtils.replace(name, "'", "''");
    }


}
