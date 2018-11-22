package com.floragunn.custom.rdbms;

import com.mysql.cj.jdbc.MysqlDataSource;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.sql.Connection;
import java.sql.SQLException;

public abstract class RdbmsBackend {

    public static final String CONFIG_KEY_JDBC_URL = "jdbc_url";
    public static final String CONFIG_KEY_JDBC_USER = "jdbc_user";
    public static final String CONFIG_KEY_JDBC_PASSWORD = "jdbc_password";
    public static final String CONFIG_KEY_JDBC_DATABASE = "jdbc_database";

    protected final static Logger log = LogManager.getLogger(RdbmsBackend.class);

    protected String jdbcURL;
    protected String jdbcUser;
    protected String jdbcPassword;
    protected String jdbcDatabase;

    /**
     * Creates connection to RDMBS
     *
     * @return
     */
    protected Connection getConnection() {
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
