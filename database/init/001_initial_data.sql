-- Initial data for CyberLab Platform

-- Create lab categories
INSERT INTO lab_categories (id, name, slug, description, icon, color, sort_order) VALUES
(gen_random_uuid(), 'Web Application Security', 'web-apps', 'Penetration testing of web applications including SQL injection, XSS, and more', 'web', '#3498db', 1),
(gen_random_uuid(), 'Active Directory', 'active-directory', 'Windows Active Directory penetration testing and lateral movement', 'windows', '#e74c3c', 2),
(gen_random_uuid(), 'Privilege Escalation', 'privilege-escalation', 'Linux and Windows privilege escalation techniques', 'shield', '#f39c12', 3),
(gen_random_uuid(), 'Buffer Overflow', 'buffer-overflow', 'Binary exploitation and buffer overflow challenges', 'code', '#9b59b6', 4),
(gen_random_uuid(), 'Network Security', 'network-security', 'Network penetration testing and protocol analysis', 'network', '#1abc9c', 5),
(gen_random_uuid(), 'Cryptography', 'cryptography', 'Cryptographic challenges and cipher breaking', 'lock', '#34495e', 6),
(gen_random_uuid(), 'Mobile Security', 'mobile-security', 'Android and iOS application security testing', 'mobile', '#e67e22', 7),
(gen_random_uuid(), 'Cloud Security', 'cloud-security', 'AWS, Azure, and GCP security assessments', 'cloud', '#3498db', 8);

-- Create sample admin user (password: Admin123!)
-- Note: In production, this should be created through a secure initialization process
INSERT INTO users (id, username, email, password_hash, first_name, last_name, is_active, is_verified, is_admin, subscription_tier, max_concurrent_sessions) VALUES
(gen_random_uuid(), 'admin', 'admin@cyberlab.local', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewBOA2BVjxpOgjfO', 'System', 'Administrator', true, true, true, 'enterprise', 10);

-- Create sample labs
DO $$
DECLARE
    web_category_id UUID;
    ad_category_id UUID;
    privesc_category_id UUID;
BEGIN
    -- Get category IDs
    SELECT id INTO web_category_id FROM lab_categories WHERE slug = 'web-apps';
    SELECT id INTO ad_category_id FROM lab_categories WHERE slug = 'active-directory';
    SELECT id INTO privesc_category_id FROM lab_categories WHERE slug = 'privilege-escalation';

    -- Insert sample labs
    INSERT INTO labs (
        id, name, slug, description, short_description, difficulty, 
        estimated_time_hours, points, category_id, objectives, prerequisites, tags,
        vm_templates, network_config, flags, hints, is_published
    ) VALUES
    (
        gen_random_uuid(),
        'SQL Injection Playground',
        'sql-injection-playground',
        'Learn and practice SQL injection techniques on a vulnerable web application. This lab covers various types of SQL injection including union-based, boolean-based, and time-based blind injections.',
        'Practice SQL injection on a vulnerable web application',
        'beginner',
        2,
        20,
        web_category_id,
        ARRAY['Understand SQL injection vulnerabilities', 'Learn different injection techniques', 'Practice with sqlmap tool'],
        ARRAY['Basic SQL knowledge', 'Understanding of web applications'],
        ARRAY['sql-injection', 'web-security', 'database'],
        '{
            "attack_boxes": [
                {"type": "kali", "template_id": "kali-2023.4", "resources": {"cpu": 2, "ram": 2048}}
            ],
            "targets": [
                {"name": "web-server", "template_id": "dvwa-vulnerable", "ip": "10.10.1.100"}
            ]
        }'::jsonb,
        '{
            "user_network": "10.10.{user_id}.0/24",
            "vpn_enabled": true,
            "guacamole_enabled": true,
            "required_ports": [80, 443, 22]
        }'::jsonb,
        '{
            "user_flag": "HTB{sql_1nj3ct10n_m4st3r}",
            "root_flag": "HTB{r00t_4cc3ss_v14_sql}"
        }'::jsonb,
        '{
            "hints": [
                {"level": 1, "content": "Look for input fields that might be vulnerable to SQL injection", "cost": 0},
                {"level": 2, "content": "Try using single quotes to break the SQL query", "cost": 5},
                {"level": 3, "content": "Use UNION SELECT to extract data from other tables", "cost": 10}
            ]
        }'::jsonb,
        true
    ),
    (
        gen_random_uuid(),
        'Linux Privilege Escalation',
        'linux-privilege-escalation',
        'Practice privilege escalation techniques on a Linux system. Learn to identify and exploit misconfigurations, SUID binaries, and other privilege escalation vectors.',
        'Escalate privileges on a Linux system',
        'intermediate',
        3,
        30,
        privesc_category_id,
        ARRAY['Identify privilege escalation vectors', 'Exploit SUID binaries', 'Abuse file permissions'],
        ARRAY['Basic Linux knowledge', 'Command line familiarity'],
        ARRAY['privilege-escalation', 'linux', 'suid'],
        '{
            "attack_boxes": [
                {"type": "kali", "template_id": "kali-2023.4", "resources": {"cpu": 2, "ram": 2048}}
            ],
            "targets": [
                {"name": "ubuntu-server", "template_id": "ubuntu-privesc", "ip": "10.10.1.100"}
            ]
        }'::jsonb,
        '{
            "user_network": "10.10.{user_id}.0/24",
            "vpn_enabled": true,
            "guacamole_enabled": true,
            "required_ports": [22]
        }'::jsonb,
        '{
            "user_flag": "HTB{l1nux_us3r_pwn3d}",
            "root_flag": "HTB{r00t_pr1v3sc_m4st3r}"
        }'::jsonb,
        '{
            "hints": [
                {"level": 1, "content": "Check for SUID binaries using find command", "cost": 0},
                {"level": 2, "content": "Look for writable files in /etc directory", "cost": 5},
                {"level": 3, "content": "Check sudo permissions with sudo -l", "cost": 10}
            ]
        }'::jsonb,
        true
    );
END $$;
