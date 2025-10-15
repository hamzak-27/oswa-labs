-- Migration: Add container-specific fields to vm_instances table
-- Purpose: Support Docker container-based VMs alongside traditional VMs
-- Date: 2025-09-10

-- Add container-specific columns to vm_instances table
ALTER TABLE vm_instances 
ADD COLUMN IF NOT EXISTS container_id VARCHAR(100),
ADD COLUMN IF NOT EXISTS container_name VARCHAR(100),
ADD COLUMN IF NOT EXISTS container_image VARCHAR(200);

-- Add indexes for container fields (for fast lookups)
CREATE INDEX IF NOT EXISTS idx_vm_instances_container_id ON vm_instances(container_id);
CREATE INDEX IF NOT EXISTS idx_vm_instances_container_name ON vm_instances(container_name);

-- Add comments for documentation
COMMENT ON COLUMN vm_instances.container_id IS 'Docker container ID for container-based VMs';
COMMENT ON COLUMN vm_instances.container_name IS 'Docker container name for container-based VMs';
COMMENT ON COLUMN vm_instances.container_image IS 'Docker image used for container-based VMs';

-- Update the vm_instances table constraints to allow either Proxmox OR container fields
-- (Both can be null, but at least one deployment method should be specified)
