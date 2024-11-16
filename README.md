# Java Security Vulnerabilities Demo

⚠️ **WARNING: This is a deliberately vulnerable application designed for educational purposes. DO NOT deploy in production!** ⚠️

This project demonstrates various security vulnerabilities in Java web applications. It's designed to help developers understand common security pitfalls and their potential impacts.

## Prerequisites

- Java 22
- Gradle
- IDE (VSCode recommended)

## Quick Start

1. Clone the repository:

```bash
git clone [your-repo-url]
cd demo
```

2. Build the project:

```bash
gradle build
```

3. Run the application:

```bash
gradle bootRun
```

The application will start on `http://localhost:4949`

## Database Setup

The project uses H2 database with file persistence:

- Database files are stored in `./data/vulndb.mv.db`
- Initial schema and data are automatically created on first run
- Access H2 Console at: `http://localhost:4949/h2-console`

H2 Console Connection Settings:

- JDBC URL: `jdbc:h2:file:./data/vulndb`
- Username: `sa`
- Password: `password`

## Available Endpoints

### SQL Injection Vulnerabilities

- `GET /api/sqlExample?userId=1`
- `GET /api/user/profile?userId=1&profileData=test`

### Command Injection Vulnerabilities

- `GET /api/getExample?input=test`
- `POST /api/postExample`
  ```json
  {
    "input": "command"
  }
  ```

### Authentication Vulnerabilities

- `POST /api/user/login`
  ```json
  {
    "username": "admin",
    "password": "admin123"
  }
  ```

### File System Vulnerabilities

- `GET /api/readFile?path=test.txt`
- `POST /api/writeFile`
  ```json
  {
    "path": "test.txt",
    "content": "Hello"
  }
  ```

## Real-World CVE Examples

The project includes examples of real-world vulnerabilities found in popular Java frameworks and libraries:

### Spring Framework Vulnerabilities

- CVE-2022-22965 (Spring4Shell) - Remote Code Execution via Data Binding
- CVE-2018-1258 - Spring Security OAuth Authentication Bypass

### Logging Framework Vulnerabilities

- CVE-2021-44228 (Log4Shell) - Remote Code Execution via JNDI Injection
- CVE-2019-17571 - Apache Log4j Socket Server Deserialization
- CVE-2017-5645 - Log4j TCP Socket Server Unsafe Deserialization

### Database and Serialization Vulnerabilities

- CVE-2020-36518 - Jackson Polymorphic Deserialization
- CVE-2019-12384 - H2 Database Console JNDI Injection
- CVE-2015-7501 - Apache Commons Collections Unsafe Deserialization

### Authentication and Encryption Vulnerabilities

- CVE-2016-4437 - Apache Shiro Authentication Bypass (Padding Oracle)
- CVE-2020-13942 - Apache Unomi MVEL Injection

Access these examples at `/api/cve/*` endpoints. Each vulnerability is documented with:
- Original CVE reference
- Vulnerability description
- Example exploit
- Code commentary

## Sample Data

The application comes pre-loaded with test data:

### Users

- admin:admin123 (ADMIN role)
- user1:password123 (USER role)
- test:test123 (USER role)
- guest:guest123 (GUEST role)
- system:system123 (SYSTEM role)

### Cache Entries

- system_config
- user_preferences
- api_keys
- feature_flags
- system_status

## Development Notes

- The application uses Spring Boot 3.3.5
- H2 database for simplified setup and testing
- All endpoints are intentionally vulnerable
- Logging is enabled for better debugging

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/vulnerability`)
3. Commit your changes (`git commit -am 'Add new vulnerability'`)
4. Push to the branch (`git push origin feature/vulnerability`)
5. Create a Pull Request

## Disclaimer

This application contains intentional security vulnerabilities for educational purposes. It should never be:

- Deployed in a production environment
- Used as a template for real applications
- Exposed to the public internet

## License

[Your License Here]
