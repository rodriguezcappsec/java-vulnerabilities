-- Create tables if they don't exist
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255),
    password_hash VARCHAR(255),
    email VARCHAR(255),
    role VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cache (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cache_key VARCHAR(255) NOT NULL,
    cache_value TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample users if they don't exist
MERGE INTO users (username, password, email, role) 
KEY(username)
VALUES 
('admin', 'admin123', 'admin@example.com', 'ADMIN'),
('user1', 'password123', 'user1@example.com', 'USER'),
('test', 'test123', 'test@example.com', 'USER'),
('guest', 'guest123', 'guest@example.com', 'GUEST'),
('system', 'system123', 'system@example.com', 'SYSTEM');

-- Insert sample cache entries
MERGE INTO cache (cache_key, cache_value)
KEY(cache_key)
VALUES 
('system_config', '{"debug": true, "maintenance": false}'),
('user_preferences', '{"theme": "dark", "notifications": true}'),
('api_keys', '{"google": "abc123", "facebook": "xyz789"}'),
('feature_flags', '{"beta_features": true, "dark_mode": true}'),
('system_status', '{"status": "online", "last_checked": "2024-01-01"}');
