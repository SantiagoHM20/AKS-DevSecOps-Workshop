package com.vulnerable.vulnerableapp;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is used to connect to the database and execute dynamic queries to
 * illustrate SQL injection vulnerability.
 */
public class JDBCManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(JDBCManager.class);

    static final String JDBC_DRIVER = "org.h2.Driver";
    static final String DB_URL = "jdbc:h2:mem:testdb";
    static final String USER = "sa";
    static final String PASS = "";

    /**
     * Executes a fixed query with a parameterized LIKE filter.
     */
    public static List<Employee> executeEmployeesByName(String nameFilter) {

        Connection conn = null;
        PreparedStatement stmt = null;
        List<Employee> employees = new ArrayList<>();

        try {

            Class.forName(JDBC_DRIVER);
            conn = DriverManager.getConnection(DB_URL, USER, PASS);

            String sql = "SELECT * FROM Employee WHERE name LIKE ?";
            stmt = conn.prepareStatement(sql);
            stmt.setString(1, "%" + (nameFilter == null ? "" : nameFilter) + "%");

            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                Employee employee = new Employee();
                employee.setId(rs.getLong(1));
                employee.setName(rs.getString(2));
                employee.setDesignation(rs.getString(3));
                employee.setExpertise(rs.getString(4));
                employees.add(employee);
                //System.out.println(rs.getString(1));
                //System.out.println(rs.getString(2));
                //System.out.println(rs.getString(3));
                //System.out.println(rs.getString(4));
            }

            stmt.close();
            conn.close();
        } catch (SQLException se) {
            LOGGER.error("Database query execution failed", se);
        } catch (ClassNotFoundException e) {
            LOGGER.error("JDBC driver not found", e);
        } finally {
            try {
                if (stmt != null)
                    stmt.close();
            } catch (SQLException se2) {
                LOGGER.warn("Failed to close JDBC statement", se2);
            }
            try {
                if (conn != null)
                    conn.close();
            } catch (SQLException se) {
                LOGGER.warn("Failed to close JDBC connection", se);
            }
        }
        return employees;
    }

    public static List<Employee> executeQuery(String ignoredUserInput) {
        return executeEmployeesByName(ignoredUserInput);
    }
}