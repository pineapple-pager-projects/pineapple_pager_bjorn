-- Test database with sensitive data for Bjorn testing
-- This data will be "stolen" by steal_data_sql.py

USE testdb;

-- Create users table with credentials
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(100) NOT NULL,
    email VARCHAR(100),
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (username, password, email, role) VALUES
('admin', 'admin123', 'admin@example.com', 'admin'),
('john.doe', 'password123', 'john@example.com', 'user'),
('jane.smith', 'letmein', 'jane@example.com', 'user'),
('root', 'toor', 'root@example.com', 'superadmin'),
('test', 'test', 'test@example.com', 'user');

-- Create sensitive data table
CREATE TABLE IF NOT EXISTS credit_cards (
    id INT AUTO_INCREMENT PRIMARY KEY,
    card_holder VARCHAR(100) NOT NULL,
    card_number VARCHAR(20) NOT NULL,
    expiry VARCHAR(10),
    cvv VARCHAR(5)
);

INSERT INTO credit_cards (card_holder, card_number, expiry, cvv) VALUES
('John Doe', '4111111111111111', '12/25', '123'),
('Jane Smith', '5500000000000004', '06/26', '456'),
('Test User', '340000000000009', '03/27', '789');

-- Create API keys table
CREATE TABLE IF NOT EXISTS api_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    service VARCHAR(50) NOT NULL,
    api_key VARCHAR(100) NOT NULL,
    secret VARCHAR(100)
);

INSERT INTO api_keys (service, api_key, secret) VALUES
('AWS', 'AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'),
('Stripe', 'sk_fake_XXXXXXXXXXXXXXXXXXXXXXXXXXX', 'whsec_fake_secret'),
('Twilio', 'ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', 'your_auth_token');

-- Grant all privileges to admin user
GRANT ALL PRIVILEGES ON testdb.* TO 'admin'@'%';
FLUSH PRIVILEGES;
