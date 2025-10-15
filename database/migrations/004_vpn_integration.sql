-- Migration: 004_vpn_integration.sql
-- Description: Add VPN certificate management and tracking to the database
-- Author: CyberLab Platform
-- Date: 2025-01-25

-- Add VPN certificates table
CREATE TABLE vpn_certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id UUID REFERENCES lab_sessions(id) ON DELETE SET NULL,
    common_name VARCHAR(255) NOT NULL UNIQUE,
    certificate_pem TEXT NOT NULL,
    private_key_pem TEXT NOT NULL,
    serial_number BIGINT NOT NULL UNIQUE,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired')),
    issued_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE NULL,
    revocation_reason VARCHAR(100) NULL,
    client_config TEXT NULL, -- Cached OpenVPN client configuration
    last_connected_at TIMESTAMP WITH TIME ZONE NULL,
    connection_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Add indexes for performance
CREATE INDEX idx_vpn_certificates_user_id ON vpn_certificates(user_id);
CREATE INDEX idx_vpn_certificates_session_id ON vpn_certificates(session_id);
CREATE INDEX idx_vpn_certificates_status ON vpn_certificates(status);
CREATE INDEX idx_vpn_certificates_expires_at ON vpn_certificates(expires_at);
CREATE INDEX idx_vpn_certificates_common_name ON vpn_certificates(common_name);

-- Add VPN-related fields to users table
ALTER TABLE users ADD COLUMN vpn_enabled BOOLEAN DEFAULT TRUE;
ALTER TABLE users ADD COLUMN max_vpn_certificates INTEGER DEFAULT 3;
ALTER TABLE users ADD COLUMN vpn_bandwidth_limit_mbps INTEGER DEFAULT 100; -- MB/s limit

-- Add VPN-related fields to lab_sessions table  
ALTER TABLE lab_sessions ADD COLUMN vpn_certificate_id UUID REFERENCES vpn_certificates(id) ON DELETE SET NULL;
ALTER TABLE lab_sessions ADD COLUMN vpn_connected_at TIMESTAMP WITH TIME ZONE NULL;
ALTER TABLE lab_sessions ADD COLUMN vpn_disconnected_at TIMESTAMP WITH TIME ZONE NULL;
ALTER TABLE lab_sessions ADD COLUMN vpn_client_ip INET NULL;

-- Create VPN connection log table for monitoring
CREATE TABLE vpn_connection_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    certificate_id UUID NOT NULL REFERENCES vpn_certificates(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id UUID REFERENCES lab_sessions(id) ON DELETE SET NULL,
    client_ip INET NOT NULL,
    vpn_ip INET NOT NULL,
    connected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    disconnected_at TIMESTAMP WITH TIME ZONE NULL,
    bytes_received BIGINT DEFAULT 0,
    bytes_sent BIGINT DEFAULT 0,
    disconnect_reason VARCHAR(100) NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Add indexes for VPN connection logs
CREATE INDEX idx_vpn_connection_logs_certificate_id ON vpn_connection_logs(certificate_id);
CREATE INDEX idx_vpn_connection_logs_user_id ON vpn_connection_logs(user_id);
CREATE INDEX idx_vpn_connection_logs_session_id ON vpn_connection_logs(session_id);
CREATE INDEX idx_vpn_connection_logs_connected_at ON vpn_connection_logs(connected_at);

-- Create trigger function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_vpn_certificate_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for vpn_certificates table
CREATE TRIGGER trigger_vpn_certificates_updated_at
    BEFORE UPDATE ON vpn_certificates
    FOR EACH ROW
    EXECUTE FUNCTION update_vpn_certificate_updated_at();

-- Create function to automatically expire certificates
CREATE OR REPLACE FUNCTION expire_vpn_certificates()
RETURNS INTEGER AS $$
DECLARE
    expired_count INTEGER;
BEGIN
    UPDATE vpn_certificates 
    SET status = 'expired'
    WHERE status = 'active' 
    AND expires_at < CURRENT_TIMESTAMP;
    
    GET DIAGNOSTICS expired_count = ROW_COUNT;
    RETURN expired_count;
END;
$$ LANGUAGE plpgsql;

-- Create function to clean up old connection logs (keep last 30 days)
CREATE OR REPLACE FUNCTION cleanup_vpn_connection_logs()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM vpn_connection_logs
    WHERE connected_at < CURRENT_TIMESTAMP - INTERVAL '30 days';
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Insert default VPN configuration settings
INSERT INTO system_settings (key, value, description, created_at, updated_at) VALUES
('vpn.server.enabled', 'true', 'Enable VPN server functionality', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('vpn.server.port', '1194', 'OpenVPN server port', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('vpn.server.protocol', 'udp', 'OpenVPN server protocol (udp/tcp)', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('vpn.server.subnet', '10.8.0.0/24', 'VPN client IP subnet', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('vpn.certificate.validity_days', '30', 'Default certificate validity in days', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('vpn.certificate.key_size', '2048', 'Certificate key size in bits', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('vpn.max_concurrent_connections', '100', 'Maximum concurrent VPN connections', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT (key) DO NOTHING;

-- Add comments for documentation
COMMENT ON TABLE vpn_certificates IS 'Stores VPN client certificates and their metadata';
COMMENT ON TABLE vpn_connection_logs IS 'Logs VPN connection events and statistics';
COMMENT ON COLUMN vpn_certificates.common_name IS 'Unique certificate common name (usually username-timestamp)';
COMMENT ON COLUMN vpn_certificates.serial_number IS 'Certificate serial number for revocation';
COMMENT ON COLUMN vpn_certificates.client_config IS 'Cached OpenVPN client configuration file content';
COMMENT ON COLUMN users.vpn_enabled IS 'Whether user is allowed to use VPN access';
COMMENT ON COLUMN users.max_vpn_certificates IS 'Maximum number of active certificates per user';