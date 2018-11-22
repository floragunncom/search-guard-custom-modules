package com.floragunn.custom.rdbms;

import com.floragunn.searchguard.auth.AuthorizationBackend;
import com.floragunn.searchguard.user.AuthCredentials;
import com.floragunn.searchguard.user.User;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.common.settings.Settings;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.LinkedList;
import java.util.List;

public class RdbmsAuthorizationBackend extends RdbmsBackend implements AuthorizationBackend {

    private final String AUTHORISATION_QUERY = "SELECT role FROM user_roles where username = ?";

    public RdbmsAuthorizationBackend(final Settings settings, final Path configPath) {
        jdbcURL = settings.get(CONFIG_KEY_JDBC_URL);
        jdbcUser = settings.get(CONFIG_KEY_JDBC_USER);
        jdbcPassword = settings.get(CONFIG_KEY_JDBC_PASSWORD);
        jdbcDatabase = settings.get(CONFIG_KEY_JDBC_DATABASE);
    }

    @Override
    public String getType() {
        return "RdbmsAuthorizationBackend";
    }

    @Override
    public void fillRoles(User user, AuthCredentials authCredentials) throws ElasticsearchSecurityException {
        user.addRoles(fetchUserRoles(user.getName()));
    }

    private List<String> fetchUserRoles(String username) {
        List<String> roles = new LinkedList<>();
        try {
            Connection con = getConnection();
            PreparedStatement stmt = con.prepareStatement(AUTHORISATION_QUERY);
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                roles.add(rs.getString(1));
            }
            con.close();
        } catch (SQLException e) {
            log.error("SQL failed with: " + e.getMessage());
            throw new RdbmsAuthException("Fetching user's hash failed");
        }
        return roles;
    }
}
