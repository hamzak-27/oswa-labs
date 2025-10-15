-- Session Management Database Schema Updates
-- Run this after the initial data setup

-- Add container tracking columns to vm_instances
ALTER TABLE vm_instances 
ADD COLUMN IF NOT EXISTS container_id VARCHAR(100),
ADD COLUMN IF NOT EXISTS container_name VARCHAR(100),
ADD COLUMN IF NOT EXISTS container_image VARCHAR(200);

-- Update lab_sessions to include Docker Compose configuration
ALTER TABLE lab_sessions 
ADD COLUMN IF NOT EXISTS docker_compose_config JSONB,
ADD COLUMN IF NOT EXISTS network_name VARCHAR(100);

-- Create user_networks table for network management
CREATE TABLE IF NOT EXISTS user_networks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    session_id UUID REFERENCES lab_sessions(id) ON DELETE CASCADE,
    network_range VARCHAR(20) NOT NULL, -- "10.10.123.0/24"
    docker_network_name VARCHAR(100) NOT NULL,
    docker_network_id VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    removed_at TIMESTAMP WITH TIME ZONE,
    
    -- Ensure unique network per user
    CONSTRAINT unique_user_network UNIQUE (user_id, docker_network_name)
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_user_networks_user_id ON user_networks(user_id);
CREATE INDEX IF NOT EXISTS idx_user_networks_session_id ON user_networks(session_id);
CREATE INDEX IF NOT EXISTS idx_vm_instances_container_id ON vm_instances(container_id);
CREATE INDEX IF NOT EXISTS idx_lab_sessions_status ON lab_sessions(status);
CREATE INDEX IF NOT EXISTS idx_lab_sessions_expires_at ON lab_sessions(expires_at);

-- Add comments for documentation
COMMENT ON TABLE user_networks IS 'Tracks Docker networks allocated to users for lab sessions';
COMMENT ON COLUMN lab_sessions.docker_compose_config IS 'Stores Docker Compose configuration for the lab session';
COMMENT ON COLUMN lab_sessions.network_name IS 'Name of the Docker network for this session';
COMMENT ON COLUMN vm_instances.container_id IS 'Docker container ID';
COMMENT ON COLUMN vm_instances.container_name IS 'Docker container name';

-- Create a view for active sessions with network info
CREATE OR REPLACE VIEW active_sessions_with_networks AS
SELECT 
    ls.id as session_id,
    ls.user_id,
    ls.lab_id,
    ls.status,
    ls.access_method,
    ls.network_range,
    ls.expires_at,
    ls.started_at,
    un.docker_network_name,
    un.docker_network_id,
    l.name as lab_name,
    u.username,
    COUNT(vm.id) as vm_count
FROM lab_sessions ls
LEFT JOIN user_networks un ON ls.id = un.session_id
LEFT JOIN labs l ON ls.lab_id = l.id  
LEFT JOIN users u ON ls.user_id = u.id
LEFT JOIN vm_instances vm ON ls.id = vm.session_id
WHERE ls.status IN ('provisioning', 'active', 'paused')
GROUP BY ls.id, un.docker_network_name, un.docker_network_id, l.name, u.username;

-- Function to cleanup expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
    expired_count INTEGER := 0;
    session_record RECORD;
BEGIN
    -- Get expired sessions
    FOR session_record IN 
        SELECT id, user_id, network_range 
        FROM lab_sessions 
        WHERE expires_at < NOW() 
        AND status IN ('active', 'provisioning', 'paused')
    LOOP
        -- Update session status to expired
        UPDATE lab_sessions 
        SET status = 'expired', stopped_at = NOW()
        WHERE id = session_record.id;
        
        -- Update VM instances to stopped
        UPDATE vm_instances 
        SET status = 'stopped', stopped_at = NOW()
        WHERE session_id = session_record.id;
        
        -- Mark network as removed (actual Docker cleanup happens in application)
        UPDATE user_networks 
        SET removed_at = NOW()
        WHERE session_id = session_record.id;
        
        expired_count := expired_count + 1;
    END LOOP;
    
    RETURN expired_count;
END;
$$ LANGUAGE plpgsql;

-- Create a function to get user session summary
CREATE OR REPLACE FUNCTION get_user_session_summary(p_user_id UUID)
RETURNS TABLE (
    total_sessions BIGINT,
    active_sessions BIGINT,
    total_lab_time_hours NUMERIC,
    labs_completed BIGINT,
    current_network_range TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        COUNT(*) as total_sessions,
        COUNT(*) FILTER (WHERE ls.status IN ('active', 'provisioning', 'paused')) as active_sessions,
        COALESCE(ROUND(SUM(EXTRACT(EPOCH FROM (COALESCE(ls.stopped_at, NOW()) - ls.started_at))/3600), 2), 0) as total_lab_time_hours,
        COUNT(*) FILTER (WHERE up.status = 'completed') as labs_completed,
        STRING_AGG(ls.network_range, ', ') FILTER (WHERE ls.status = 'active') as current_network_range
    FROM lab_sessions ls
    LEFT JOIN user_progress up ON ls.user_id = up.user_id AND ls.lab_id = up.lab_id
    WHERE ls.user_id = p_user_id;
END;
$$ LANGUAGE plpgsql;
