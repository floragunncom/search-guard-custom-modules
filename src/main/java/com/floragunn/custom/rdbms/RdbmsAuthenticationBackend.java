package com.floragunn.custom.rdbms;

import com.floragunn.searchguard.auth.AuthenticationBackend;
import com.floragunn.searchguard.user.AuthCredentials;
import com.floragunn.searchguard.user.User;
import com.google.common.hash.Hashing;
import com.mysql.cj.jdbc.MysqlDataSource;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.common.settings.Settings;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class RdbmsHttpAuthenticator implements AuthenticationBackend {

    private final static Logger log = LogManager.getLogger(RdbmsHttpAuthenticator.class);

    public static final String CONFIG_KEY_JDBC_URL = "jdbc_url";
    public static final String CONFIG_KEY_JDBC_USER = "jdbc_user";
    public static final String CONFIG_KEY_JDBC_PASSWORD = "jdbc_password";
    public static final String CONFIG_KEY_JDBC_DATABASE = "jdbc_database";


    private final String AUTHENTICATE_QUERY = "SELECT hash FROM users where username = ?";

    private String jdbcURL;
    private String jdbcUser;
    private String jdbcPassword;
    private String jdbcDatabase;

    public RdbmsHttpAuthenticator(String jdbcURL, String jdbcUser, String jdbcPassword, String jdbcDatabase) {
        this.jdbcURL = jdbcURL;
        this.jdbcUser = jdbcUser;
        this.jdbcPassword = jdbcPassword;
        this.jdbcDatabase = jdbcDatabase;
    }

    public RdbmsHttpAuthenticator(final Settings settings, final Path configPath) {
        jdbcURL = settings.get(CONFIG_KEY_JDBC_URL);
        jdbcUser = settings.get(CONFIG_KEY_JDBC_USER);
        jdbcPassword = settings.get(CONFIG_KEY_JDBC_PASSWORD);
        jdbcDatabase = settings.get(CONFIG_KEY_JDBC_DATABASE);
    }

    public String getType() {
        return "RdbmsHttpAuthenticator";
    }

    public User authenticate(AuthCredentials credentials) throws ElasticsearchSecurityException {
        String rdbmsHash = getUserPasswordHash(credentials.getUsername());

        String requestHash = Hashing.sha256()
                .hashString(new String(credentials.getPassword()), StandardCharsets.UTF_8)
                .toString();

        if (rdbmsHash == null) {
            throw new ElasticsearchSecurityException(
                    String.format("User %s does not exist", credentials.getUsername())
            );
        } else if (!rdbmsHash.equals(requestHash)) {
            throw new ElasticsearchSecurityException("User/Password do not match");
        }

        return new User(credentials.getUsername());
    }

    public boolean exists(User user) {
        return getUserPasswordHash(user.getName()) != null;
    }

    private String getUserPasswordHash(String username) {
        String passwordHash;
        try {
            Connection con = getConnection();
            PreparedStatement stmt = con.prepareStatement(AUTHENTICATE_QUERY);
            stmt.setString(1, username);
            ResultSet rs=stmt.executeQuery();
            passwordHash = rs.next() ? rs.getString(1) : null;
            con.close();
        } catch (SQLException e) {
            log.error("SQL failed with: " + e.getMessage());
            throw new RdbmsAuthException("Fetching user's hash failed");
        }
        return passwordHash;
    }

    private Connection getConnection() {
        return AccessController.doPrivileged(new PrivilegedAction<Connection>() {
                    public Connection run() {
                        MysqlDataSource dataSource = new MysqlDataSource();
                        dataSource.setUser(jdbcUser);
                        dataSource.setPassword(jdbcPassword);
                        dataSource.setServerName(jdbcURL);
                        dataSource.setDatabaseName(jdbcDatabase);

                        try {
                            return dataSource.getConnection();
                        } catch (SQLException e) {
                            log.error("SQL failed with: " + e.getMessage());
                            throw new RdbmsAuthException("Connecting RDBMS failed");
                        }
                    }
                });
    }

}
