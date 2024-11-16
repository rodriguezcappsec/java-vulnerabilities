package com.example.demo.routes;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Key;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Base64;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import jakarta.servlet.http.HttpServletResponse;

@Controller
@RequestMapping("/api")
public class VulnerableJavaSnippets {

    private static final String DB_URL = "jdbc:h2:file:./data/vulndb;MODE=MySQL";
    private static final String DB_USER = "sa";
    private static final String DB_PASSWORD = "password";

    private Connection getConnection() throws SQLException {
        return DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
    }

    @GetMapping("/getExample")
    public void getExample(@RequestParam(name = "input") String input, HttpServletResponse response)
            throws IOException {
        response.setContentType("text/html");
        response.getWriter().write("<html><body>User Input: " + input + "</body></html>");
    }

    @GetMapping("/redirect")
    public void redirectExample(@RequestParam(name = "url") String url, HttpServletResponse response)
            throws IOException {
        response.sendRedirect(url);
    }

    @DeleteMapping("/deleteExample")
    public void deleteExample(@RequestParam(name = "xml") String xml, HttpServletResponse response) throws IOException {
        response.setContentType("text/plain");
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
            DocumentBuilder db = dbf.newDocumentBuilder();
            InputSource is = new InputSource(new StringReader(xml));
            Document doc = db.parse(is);
            response.getWriter().write("Parsed XML");
        } catch (Exception e) {
            response.getWriter().write("Error parsing XML");
        }
    }

    @RequestMapping(value = "/optionsExample", method = RequestMethod.OPTIONS)
    public void optionsExample(@RequestParam(name = "js", required = false, defaultValue = "") String js,
            HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        response.getWriter().write("<script>" + js + "</script>");
    }

    @PostMapping("/connectExample")
    public void connectExample(@RequestParam(name = "data") String data, HttpServletResponse response)
            throws IOException {
        response.setContentType("text/plain");
        try {
            String secret = "ThisIsASecretKey";
            Key key = new SecretKeySpec(secret.getBytes(), "DES");
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedData = cipher.doFinal(data.getBytes());
            response.getWriter().write("Encrypted Data: " + Base64.getEncoder().encodeToString(encryptedData));
        } catch (Exception e) {
            response.getWriter().write("Encryption error");
        }
    }

    @PostMapping("/sqlExample")
    public void sqlExample(@RequestParam(name = "userId") String userId, HttpServletResponse response)
            throws IOException {
        response.setContentType("text/plain");
        try {
            Connection conn = getConnection();
            String query = "SELECT * FROM users WHERE id = '" + userId + "'";
            PreparedStatement stmt = conn.prepareStatement(query);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                response.getWriter().write("User Found: " + rs.getString("name"));
            } else {
                response.getWriter().write("User Not Found");
            }
        } catch (Exception e) {
            response.getWriter().write("Database error");
        }
    }

    @PostMapping("/hashExample")
    public void hashExample(@RequestParam(name = "password") String password, HttpServletResponse response)
            throws IOException {
        response.setContentType("text/plain");
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(password.getBytes());
            response.getWriter().write("Hashed Password: " + Base64.getEncoder().encodeToString(hash));
        } catch (Exception e) {
            response.getWriter().write("Hashing error");
        }
    }

    @GetMapping("/user/profile")
    public void userProfile(@RequestParam(name = "userId") String userId,
            @RequestParam(name = "profileData") String profileData,
            HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        try {
            Connection conn = getConnection();
            String query = "SELECT * FROM users WHERE id = '" + userId + "'";
            PreparedStatement stmt = conn.prepareStatement(query);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                String username = rs.getString("username");
                String email = rs.getString("email");
                String profileHtml = "<h1>Profile for " + username + "</h1><p>Email: " + email + "</p>";
                profileHtml += "<script>var profileData = '" + profileData + "';</script>";
                response.getWriter().write(profileHtml);
            } else {
                response.getWriter().write("User Not Found");
            }
        } catch (IOException | SQLException e) {
            response.getWriter().write("Database error" + e.getMessage());
        }
    }

    @PostMapping("/file/upload")
    public void fileUpload(@RequestParam(name = "file") MultipartFile file,
            @RequestParam(name = "fileName") String fileName,
            HttpServletResponse response) throws IOException {
        response.setContentType("text/plain");
        try {
            String uploadDir = "/uploads/";
            File uploadFile = new File(uploadDir + fileName);
            if (!uploadFile.exists()) {
                uploadFile.createNewFile();
            }
            try (FileOutputStream fos = new FileOutputStream(uploadFile)) {
                fos.write(file.getBytes());
            }
            response.getWriter().write("File uploaded successfully");
        } catch (IOException e) {
            response.getWriter().write("Upload error");
        }
    }

    @PostMapping("/payment/process")
    public void processPayment(@RequestParam(name = "cardNumber") String cardNumber,
            @RequestParam(name = "expirationDate") String expirationDate,
            @RequestParam(name = "cvv") String cvv,
            HttpServletResponse response) throws IOException {
        response.setContentType("text/plain");
        try {
            String paymentGatewayUrl = "https://payment-gateway.com/process";
            URL url = new URL(paymentGatewayUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            String postData = "cardNumber=" + cardNumber + "&expirationDate=" + expirationDate + "&cvv=" + cvv;
            conn.setDoOutput(true);
            OutputStream os = conn.getOutputStream();
            os.write(postData.getBytes());
            os.close();
            int responseCode = conn.getResponseCode();
            if (responseCode == 200) {
                response.getWriter().write("Payment processed successfully");
            } else {
                response.getWriter().write("Payment error");
            }
        } catch (Exception e) {
            response.getWriter().write("Payment error");
        }
    }

    @PostMapping("/admin/dashboard")
    public void adminDashboard(@RequestParam(name = "username") String username,
            @RequestParam(name = "password") String password,
            HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        try {
            String adminUsername = "admin";
            String adminPassword = "password123";
            if (username.equals(adminUsername) && password.equals(adminPassword)) {
                String dashboardHtml = "<h1>Admin Dashboard</h1><p>Welcome, " + username + "</p>";
                dashboardHtml += "<script>var adminToken = '" + generateAdminToken() + "';</script>";
                response.getWriter().write(dashboardHtml);
            } else {
                response.getWriter().write("Invalid credentials");
            }
        } catch (Exception e) {
            response.getWriter().write("Error");
        }
    }

    private String generateAdminToken() {
        String token = UUID.randomUUID().toString();
        // Store the token in a database or cache
        return token;
    }

    @PostMapping("/user/register")
    public void registerUser(@RequestParam(name = "username") String username,
            @RequestParam(name = "password") String password, HttpServletResponse response)
            throws IOException {
        response.setContentType("text/plain");
        try {
            Connection conn = getConnection();
            String query = "INSERT INTO users (username, password) VALUES ('" + username + "', '" + password + "')";
            PreparedStatement stmt = conn.prepareStatement(query);
            stmt.executeUpdate();
            response.getWriter().write("User registered successfully");
        } catch (Exception e) {
            response.getWriter().write("Registration error");
        }
    }

    @PostMapping("/user/settings")
    public void updateSettings(@RequestParam(name = "username") String username,
            @RequestParam(name = "email") String email, HttpServletResponse response)
            throws IOException {
        response.setContentType("text/plain");
        try {
            Connection conn = getConnection();
            String query = "UPDATE users SET email = '" + email + "' WHERE username = '" + username + "'";
            PreparedStatement stmt = conn.prepareStatement(query);
            stmt.executeUpdate();
            response.getWriter().write("Settings updated successfully");
        } catch (Exception e) {
            response.getWriter().write("Update error");
        }
    }

    @PostMapping("/user/delete")
    public void deleteUser(@RequestParam(name = "username") String username,
            @RequestParam(name = "password") String password, HttpServletResponse response)
            throws IOException {
        response.setContentType("text/plain");
        try {
            Connection conn = getConnection();
            String query = "DELETE FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
            PreparedStatement stmt = conn.prepareStatement(query);
            stmt.executeUpdate();
            response.getWriter().write("User deleted successfully");
        } catch (Exception e) {
            response.getWriter().write("Delete error");
        }
    }

    @PostMapping("/user/login")
    public void userLogin(@RequestParam(name = "username") String username,
            @RequestParam(name = "password") String password, HttpServletResponse response)
            throws IOException {
        response.setContentType("text/plain");
        try {
            Connection conn = getConnection();
            String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
            PreparedStatement stmt = conn.prepareStatement(query);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                response.getWriter().write("Login successful");
            } else {
                response.getWriter().write("Invalid credentials");
            }
        } catch (Exception e) {
            response.getWriter().write("Login error");
        }
    }

    @PostMapping("/user/create")
    public void createUser(@RequestParam(name = "username") String username,
            @RequestParam(name = "password") String password, HttpServletResponse response)
            throws IOException {
        response.setContentType("text/plain");
        try {
            Connection conn = getConnection();
            String query = "INSERT INTO users (username, password) VALUES (?, ?)";
            PreparedStatement stmt = conn.prepareStatement(query);
            stmt.setString(1, username);
            stmt.setString(2, password);
            stmt.executeUpdate();
            response.getWriter().write("User created successfully");
        } catch (Exception e) {
            response.getWriter().write("Create error");
        }
    }

    @PostMapping("/user/update")
    public void updateUser(@RequestParam(name = "username") String username, @RequestParam(name = "email") String email,
            HttpServletResponse response)
            throws IOException {
        response.setContentType("text/plain");
        try {
            Connection conn = getConnection();
            String query = "UPDATE users SET email = '" + email + "' WHERE username = '" + username + "'";
            PreparedStatement stmt = conn.prepareStatement(query);
            stmt.executeUpdate();
            response.getWriter().write("User updated successfully");
        } catch (Exception e) {
            response.getWriter().write("Update error");
        }
    }

    @PostMapping("/file/delete")
    public void deleteFile(@RequestParam(name = "fileName") String fileName, HttpServletResponse response)
            throws IOException {
        response.setContentType("text/plain");
        try {
            String deleteDir = "/uploads/";
            File deleteFile = new File(deleteDir + fileName);
            if (deleteFile.exists()) {
                deleteFile.delete();
                response.getWriter().write("File deleted successfully");
            } else {
                response.getWriter().write("File not found");
            }
        } catch (Exception e) {
            response.getWriter().write("Delete error");
        }
    }

    @PostMapping("/file/download")
    public void downloadFile(@RequestParam(name = "fileName") String fileName, HttpServletResponse response)
            throws IOException {
        response.setContentType("application/octet-stream");
        try {
            String downloadDir = "/downloads/";
            File downloadFile = new File(downloadDir + fileName);
            if (downloadFile.exists()) {
                FileInputStream fis = new FileInputStream(downloadFile);
                byte[] fileData = new byte[(int) downloadFile.length()];
                fis.read(fileData);
                fis.close();
                response.setHeader("Content-Disposition", "attachment; filename=\"" + fileName + "\"");
                response.getOutputStream().write(fileData);
            } else {
                response.getWriter().write("File not found");
            }
        } catch (Exception e) {
            response.getWriter().write("Download error");
        }
    }

    public void ldapExample(@RequestParam(name = "username") String username, HttpServletResponse response)
            throws IOException {
        response.setContentType("text/plain");
        String filter = "(uid=" + username + ")";
        response.getWriter().write("LDAP Filter: " + filter);
    }

    @PostMapping("/deserializeExample")
    public void deserializeExample(@RequestParam(name = "object") String object, HttpServletResponse response)
            throws IOException {
        response.setContentType("text/plain");
        try {
            java.io.ByteArrayInputStream bis = new java.io.ByteArrayInputStream(Base64.getDecoder().decode(object));
            java.io.ObjectInputStream ois = new java.io.ObjectInputStream(bis);
            Object obj = ois.readObject();
            response.getWriter().write("Deserialized Object: " + obj.toString());
        } catch (Exception e) {
            response.getWriter().write("Deserialization error");
        }
    }

    @GetMapping("/insecureRandomExample")
    public void insecureRandomExample(HttpServletResponse response) throws IOException {
        response.setContentType("text/plain");
        double randomNumber = Math.random();
        response.getWriter().write("Generated Random Number: " + randomNumber);
    }

    @PostMapping("/config/update")
    public void updateConfig(@RequestParam(name = "configData") String configData, HttpServletResponse response)
            throws IOException {
        response.setContentType("text/plain");
        try {
            Process process = Runtime.getRuntime().exec("cmd.exe /c echo " + configData + " > config.txt");
            process.waitFor();
            response.getWriter().write("Configuration updated successfully");
        } catch (Exception e) {
            response.getWriter().write("Update failed");
        }
    }

    @GetMapping("/backup/download")
    public void downloadBackup(@RequestParam(name = "filename") String filename, HttpServletResponse response)
            throws IOException {
        File file = new File("./backups/" + filename);
        if (file.exists()) {
            response.setContentType("application/octet-stream");
            FileInputStream fis = new FileInputStream(file);
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                response.getOutputStream().write(buffer, 0, bytesRead);
            }
            fis.close();
        }
    }

    @PostMapping("/user/import")
    public void importUserData(@RequestParam(name = "data") String data, HttpServletResponse response)
            throws IOException {
        response.setContentType("text/plain");
        try {
            Class<?> type = Class.forName(data);
            Object instance = type.newInstance();
            response.getWriter().write("User data imported: " + instance.toString());
        } catch (Exception e) {
            response.getWriter().write("Import failed");
        }
    }

    @GetMapping("/system/check")
    public void checkSystem(@RequestParam(name = "command") String command, HttpServletResponse response)
            throws IOException {
        response.setContentType("text/plain");
        StringBuilder output = new StringBuilder();
        try {
            ProcessBuilder pb = new ProcessBuilder();
            pb.command("cmd.exe", "/c", command);
            Process process = pb.start();
            java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            response.getWriter().write(output.toString());
        } catch (Exception e) {
            response.getWriter().write("Check failed");
        }
    }

    @PostMapping("/cache/clear")
    public void clearCache(@RequestParam(name = "key") String key, HttpServletResponse response) throws IOException {
        response.setContentType("text/plain");
        try {
            Connection conn = getConnection();
            String query = "DELETE FROM cache WHERE cache_key LIKE '%" + key + "%'";
            conn.createStatement().execute(query);
            response.getWriter().write("Cache cleared successfully");
        } catch (Exception e) {
            response.getWriter().write("Cache clear failed");
        }
    }

    private static final String ENCRYPTION_KEY = "MyS3cretK3y!123";

    @PostMapping("/data/encrypt")
    public void encryptData(@RequestParam(name = "data") String data, HttpServletResponse response) throws IOException {
        response.setContentType("text/plain");
        try {
            Key key = new SecretKeySpec(ENCRYPTION_KEY.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encrypted = cipher.doFinal(data.getBytes());
            response.getWriter().write(Base64.getEncoder().encodeToString(encrypted));
        } catch (Exception e) {
            response.getWriter().write("Encryption failed");
        }
    }

    private static ThreadLocal<String> userContext = new ThreadLocal<>();

    @PostMapping("/auth/login")
    public void authenticateUser(@RequestParam(name = "username") String username,
            @RequestParam(name = "password") String password,
            HttpServletResponse response) throws IOException {
        response.setContentType("text/plain");
        try {
            userContext.set(username);
            String hashedPassword = password;
            for (int i = 0; i < 3; i++) {
                hashedPassword = new String(MessageDigest.getInstance("SHA-1").digest(hashedPassword.getBytes()));
            }
            Connection conn = getConnection();
            ResultSet rs = conn.createStatement().executeQuery(
                    "SELECT * FROM users WHERE username='" + username + "' AND password_hash='" + hashedPassword + "'");
            if (rs.next()) {
                String sessionId = UUID.randomUUID().toString();
                response.addHeader("Set-Cookie", "session=" + sessionId + "; Path=/");
                response.getWriter().write("Login successful");
            }
        } catch (Exception e) {
            response.getWriter().write("Authentication failed");
        }
    }

    @PostMapping("/document/process")
    public void processDocument(@RequestParam(name = "xmlData") String xmlData, HttpServletResponse response)
            throws IOException {
        response.setContentType("text/plain");
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setXIncludeAware(true);
            factory.setExpandEntityReferences(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
            response.getWriter().write("Document processed: " + doc.getDocumentElement().getNodeName());
        } catch (Exception e) {
            response.getWriter().write("Processing failed");
        }
    }

    private static volatile Object[] sharedResource = new Object[10];

    @PostMapping("/async/process")
    public void processAsync(@RequestParam(name = "data") String data, @RequestParam(name = "index") int index,
            HttpServletResponse response)
            throws IOException {
        response.setContentType("text/plain");
        try {
            if (index >= 0 && index < sharedResource.length) {
                Thread processor = new Thread(() -> {
                    try {
                        Thread.sleep(100);
                        sharedResource[index] = data;
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                });
                processor.start();
                response.getWriter().write("Processing started");
            }
        } catch (Exception e) {
            response.getWriter().write("Processing failed");
        }
    }

    @PostMapping("/template/render")
    public void renderTemplate(@RequestParam(name = "template") String template,
            @RequestParam(name = "data") String data, HttpServletResponse response)
            throws IOException {
        response.setContentType("text/html");
        try {
            String renderedTemplate = template.replace("${data}", data);
            response.getWriter().write(renderedTemplate);
        } catch (Exception e) {
            response.getWriter().write("Rendering failed");
        }
    }

    @PostMapping("/api/proxy")
    public void proxyRequest(@RequestParam(name = "url") String url,
            @RequestParam(name = "requestData") String requestData, HttpServletResponse response)
            throws IOException {
        response.setContentType("application/json");
        try {
            URL targetUrl = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) targetUrl.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.getOutputStream().write(requestData.getBytes());

            try (java.io.BufferedReader br = new java.io.BufferedReader(
                    new java.io.InputStreamReader(conn.getInputStream()))) {
                String output;
                StringBuilder responseData = new StringBuilder();
                while ((output = br.readLine()) != null) {
                    responseData.append(output);
                }
                response.getWriter().write(responseData.toString());
            }
        } catch (Exception e) {
            response.getWriter().write("{\"error\": \"Proxy request failed\"}");
        }
    }

    @PostMapping("/class/execute")
    public void executeCustomCode(@RequestParam(name = "className") String className,
            @RequestParam(name = "methodName") String methodName,
            HttpServletResponse response) throws IOException {
        response.setContentType("text/plain");
        try {
            // Using reflection to load and execute arbitrary methods
            Class<?> loadedClass = Class.forName(className);
            Object instance = loadedClass.getDeclaredConstructor().newInstance();
            Object result = loadedClass.getMethod(methodName).invoke(instance);
            response.getWriter().write("Method executed successfully: " + result);
        } catch (ClassNotFoundException e) {
            response.getWriter().write("Error: Class not found - " + e.getMessage());
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.getClass().getSimpleName() + " - " + e.getMessage());
        }
    }

    @PostMapping("/script/eval")
    public void evaluateScript(@RequestParam(name = "script") String script,
            HttpServletResponse response) throws IOException {
        response.setContentType("text/plain");
        try {
            // Using Runtime to execute system commands
            Process process = Runtime.getRuntime().exec(new String[] { "cmd.exe", "/c", script });
            java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            response.getWriter().write("Script output:\n" + output.toString());
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.getClass().getSimpleName() + " - " + e.getMessage());
        }
    }

    @PostMapping("/object/create")
    public void createObject(@RequestParam(name = "type") String type,
            @RequestParam(name = "data") String data,
            HttpServletResponse response) throws IOException {
        response.setContentType("text/plain");
        try {
            Class<?> clazz = Thread.currentThread().getContextClassLoader().loadClass(type);
            Object instance = clazz.getDeclaredConstructor(String.class).newInstance(data);
            response.getWriter().write("Object created: " + instance.toString());
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.getClass().getSimpleName() + " - " + e.getMessage());
        }
    }
}
