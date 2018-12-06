package com.floragunn.custom.rdbms;

import com.floragunn.searchguard.auth.AuthenticationBackend;
import com.floragunn.searchguard.user.AuthCredentials;
import com.floragunn.searchguard.user.User;
import com.google.common.hash.Hashing;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.common.settings.Settings;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class RdbmsAuthenticationBackend extends RdbmsBackend implements AuthenticationBackend {

    protected final static Logger log = LogManager.getLogger(RdbmsAuthenticationBackend.class);

    private final String AUTHENTICATION_QUERY = "SELECT hash FROM users where username = ?";

    public RdbmsAuthenticationBackend(final Settings settings, final Path configPath) {
        jdbcURL = settings.get(CONFIG_KEY_JDBC_URL);
        jdbcUser = settings.get(CONFIG_KEY_JDBC_USER);
        jdbcPassword = settings.get(CONFIG_KEY_JDBC_PASSWORD);
        jdbcDatabase = settings.get(CONFIG_KEY_JDBC_DATABASE);
    }

    public String getType() {
        return "RdbmsAuthenticationBackend";
    }

    public User authenticate(AuthCredentials credentials) throws ElasticsearchSecurityException {
        String rdbmsHash = fetchPasswordHash(credentials.getUsername());

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
        return fetchPasswordHash(user.getName()) != null;
    }

    /**
     * Returns password's hash for a given user or null if a user does not exist
     *
     * @param username
     * @return
     */
    private String fetchPasswordHash(String username) {
        String passwordHash;
        try {
            Connection con = getConnection();
            PreparedStatement stmt = con.prepareStatement(AUTHENTICATION_QUERY);
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            passwordHash = rs.next() ? rs.getString(1) : null;
            con.close();
        } catch (SQLException e) {
            log.error("SQL failed with: " + e.getMessage());
            throw new RdbmsAuthException("Fetching user's hash failed");
        }
        return passwordHash;
    }

}
