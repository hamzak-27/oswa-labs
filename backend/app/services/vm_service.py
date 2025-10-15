"""
VM service for managing Docker containers as virtual machines
"""

import docker
import asyncio
import json
import uuid
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, update
import ipaddress

from app.models.session import LabSession, VMInstance, VMStatus, SessionStatus
from app.models.lab import Lab
from app.services.network_service import NetworkService
from app.core.redis import redis_client
from app.core.config import settings
from loguru import logger


class VMService:
    """Service class for managing container-based VMs"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.docker_client = None
        self.network_service = NetworkService(db)
        self._initialize_docker_client()
    
    def _initialize_docker_client(self):
        """Initialize Docker client"""
        try:
            # Try different connection methods for Windows compatibility
            try:
                # First try from environment (should work with Docker Desktop)
                self.docker_client = docker.from_env()
                self.docker_client.ping()
            except Exception:
                # Fallback for Windows Docker Desktop
                self.docker_client = docker.DockerClient(base_url='npipe:////./pipe/dockerDesktopLinuxEngine')
                self.docker_client.ping()
            
            logger.info("VM Service: Docker client initialized successfully")
        except Exception as e:
            logger.error(f"VM Service: Failed to initialize Docker client: {e}")
            self.docker_client = None
    
    async def provision_lab_environment(self, session_id: uuid.UUID) -> Tuple[bool, str]:
        """Provision all VMs for a lab session"""
        
        if not self.docker_client:
            return False, "Docker client not available"
        
        try:
            # Get session with lab details
            session = await self._get_session_with_lab(session_id)
            if not session:
                return False, "Session not found"
            
            # Get lab VM template configuration
            vm_configs = await self._get_lab_vm_configs(session.lab_id)
            if not vm_configs:
                return False, "No VM configurations found for lab"
            
            # Create user network if not exists
            network_success, network_name = await self.network_service.create_user_network(
                session.user_id, 
                session.id, 
                session.network_range
            )
            
            if not network_success:
                return False, f"Failed to create network: {network_name}"
            
            # Provision each VM
            provisioned_vms = []
            total_resources = {"cpu": 0, "memory": 0, "storage": 0}
            
            for vm_config in vm_configs:
                success, vm_instance = await self._create_vm_instance(
                    session=session,
                    vm_config=vm_config,
                    network_name=network_name
                )
                
                if success:
                    provisioned_vms.append(vm_instance)
                    total_resources["cpu"] += vm_config.get("cpu_cores", 1)
                    total_resources["memory"] += vm_config.get("ram_mb", 512)
                    total_resources["storage"] += vm_config.get("disk_gb", 10)
                else:
                    # Cleanup on failure
                    await self._cleanup_session_vms(session_id)
                    return False, f"Failed to create VM: {vm_config['name']}"
            
            # Update session with resource allocation
            await self._update_session_resources(session_id, total_resources)
            
            # Start all VMs
            for vm_instance in provisioned_vms:
                await self._start_vm_container(vm_instance.id)
            
            logger.info(f"Provisioned {len(provisioned_vms)} VMs for session {session_id}")
            return True, f"Provisioned {len(provisioned_vms)} VMs successfully"
            
        except Exception as e:
            logger.error(f"Failed to provision lab environment for session {session_id}: {e}")
            return False, str(e)
    
    async def _create_vm_instance(
        self, 
        session: LabSession, 
        vm_config: Dict[str, Any], 
        network_name: str
    ) -> Tuple[bool, Optional[VMInstance]]:
        """Create a single VM instance (container)"""
        
        try:
            # Generate container configuration
            container_config = await self._build_container_config(
                vm_config, 
                session, 
                network_name
            )
            
            # Create VM instance record first
            vm_instance = VMInstance(
                id=uuid.uuid4(),
                session_id=session.id,
                vm_name=vm_config["name"],
                vm_type=vm_config.get("type", "unknown"),
                template_id=vm_config.get("image", "unknown"),
                status=VMStatus.CREATING,
                cpu_cores=vm_config.get("cpu_cores", 1),
                ram_mb=vm_config.get("ram_mb", 512),
                disk_gb=vm_config.get("disk_gb", 10),
                custom_config=vm_config
            )
            
            # Add container-specific fields
            vm_instance.container_id = None  # Will be set after container creation
            vm_instance.container_name = f"cyberlab_{session.user_id}_{vm_config['name']}_{str(session.id)[:8]}"
            vm_instance.container_image = vm_config["image"]
            
            self.db.add(vm_instance)
            await self.db.commit()
            await self.db.refresh(vm_instance)
            
            # Create Docker container
            container = self.docker_client.containers.create(**container_config)
            
            # Update VM instance with container details
            vm_instance.container_id = container.id
            vm_instance.status = VMStatus.STOPPED
            await self.db.commit()
            
            logger.info(f"Created VM instance {vm_instance.vm_name} (container: {container.short_id})")
            return True, vm_instance
            
        except Exception as e:
            logger.error(f"Failed to create VM instance {vm_config['name']}: {e}")
            # Cleanup database record if container creation failed
            if 'vm_instance' in locals():
                await self.db.delete(vm_instance)
                await self.db.commit()
            return False, None
    
    async def _build_container_config(
        self, 
        vm_config: Dict[str, Any], 
        session: LabSession, 
        network_name: str
    ) -> Dict[str, Any]:
        """Build Docker container configuration"""
        
        container_name = f"cyberlab_{session.user_id}_{vm_config['name']}_{str(session.id)[:8]}"
        
        # Base configuration
        config = {
            "image": vm_config["image"],
            "name": container_name,
            "detach": True,
            "hostname": vm_config["name"],
            "network": network_name,
            "labels": {
                "cyberlab.session_id": str(session.id),
                "cyberlab.user_id": str(session.user_id),
                "cyberlab.lab_id": str(session.lab_id),
                "cyberlab.vm_type": vm_config.get("type", "unknown"),
                "cyberlab.vm_name": vm_config["name"],
                "cyberlab.created_at": datetime.utcnow().isoformat()
            },
            "mem_limit": f"{vm_config.get('ram_mb', 512)}m",
            "cpu_count": vm_config.get("cpu_cores", 1),
            "restart_policy": {"Name": "unless-stopped"}
        }
        
        # Environment variables
        env_vars = {
            "CYBERLAB_SESSION_ID": str(session.id),
            "CYBERLAB_USER_ID": str(session.user_id),
            "CYBERLAB_VM_NAME": vm_config["name"],
            "CYBERLAB_VM_TYPE": vm_config.get("type", "unknown")
        }
        
        # Add lab-specific environment variables
        if "environment" in vm_config:
            env_vars.update(vm_config["environment"])
        
        config["environment"] = env_vars
        
        # Port mappings (for web access)
        if "ports" in vm_config:
            port_mappings = {}
            for port in vm_config["ports"]:
                if isinstance(port, int):
                    # Map to random host port
                    port_mappings[f"{port}/tcp"] = None
                elif isinstance(port, dict):
                    # Explicit port mapping
                    container_port = port.get("container")
                    host_port = port.get("host")
                    if container_port:
                        port_mappings[f"{container_port}/tcp"] = host_port
            
            if port_mappings:
                config["ports"] = port_mappings
        
        # Volume mounts
        if "volumes" in vm_config:
            config["volumes"] = vm_config["volumes"]
        
        # Command override
        if "command" in vm_config:
            config["command"] = vm_config["command"]
        
        # Privileged mode (for certain labs)
        if vm_config.get("privileged", False):
            config["privileged"] = True
        
        # Add capabilities if needed
        if "capabilities" in vm_config:
            config["cap_add"] = vm_config["capabilities"]
        
        return config
    
    async def _start_vm_container(self, vm_instance_id: uuid.UUID) -> bool:
        """Start a VM container"""
        
        try:
            # Get VM instance
            query = select(VMInstance).where(VMInstance.id == vm_instance_id)
            result = await self.db.execute(query)
            vm_instance = result.scalar_one_or_none()
            
            if not vm_instance or not vm_instance.container_id:
                logger.error(f"VM instance {vm_instance_id} not found or has no container")
                return False
            
            # Get container
            container = self.docker_client.containers.get(vm_instance.container_id)
            
            # Start container
            container.start()
            
            # Update status
            vm_instance.status = VMStatus.STARTING
            vm_instance.started_at = datetime.utcnow()
            await self.db.commit()
            
            # Wait for container to be ready
            await asyncio.sleep(2)
            
            # Get container details
            container.reload()
            
            # Extract IP address
            networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
            ip_address = None
            for network_info in networks.values():
                if network_info.get("IPAddress"):
                    ip_address = network_info["IPAddress"]
                    break
            
            # Update VM instance with runtime details
            vm_instance.ip_address = ip_address
            vm_instance.status = VMStatus.RUNNING
            await self.db.commit()
            
            logger.info(f"Started VM container {vm_instance.vm_name} with IP {ip_address}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start VM container {vm_instance_id}: {e}")
            # Update status to error
            if 'vm_instance' in locals() and vm_instance:
                vm_instance.status = VMStatus.ERROR
                await self.db.commit()
            return False
    
    async def stop_vm_container(self, vm_instance_id: uuid.UUID) -> bool:
        """Stop a VM container"""
        
        try:
            # Get VM instance
            query = select(VMInstance).where(VMInstance.id == vm_instance_id)
            result = await self.db.execute(query)
            vm_instance = result.scalar_one_or_none()
            
            if not vm_instance or not vm_instance.container_id:
                return True  # Already stopped or doesn't exist
            
            # Get and stop container
            container = self.docker_client.containers.get(vm_instance.container_id)
            container.stop(timeout=10)
            
            # Update status
            vm_instance.status = VMStatus.STOPPED
            vm_instance.stopped_at = datetime.utcnow()
            await self.db.commit()
            
            logger.info(f"Stopped VM container {vm_instance.vm_name}")
            return True
            
        except docker.errors.NotFound:
            # Container doesn't exist, mark as stopped
            if 'vm_instance' in locals() and vm_instance:
                vm_instance.status = VMStatus.STOPPED
                await self.db.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to stop VM container {vm_instance_id}: {e}")
            return False
    
    async def remove_vm_container(self, vm_instance_id: uuid.UUID) -> bool:
        """Remove a VM container"""
        
        try:
            # Stop first
            await self.stop_vm_container(vm_instance_id)
            
            # Get VM instance
            query = select(VMInstance).where(VMInstance.id == vm_instance_id)
            result = await self.db.execute(query)
            vm_instance = result.scalar_one_or_none()
            
            if not vm_instance or not vm_instance.container_id:
                return True
            
            # Remove container
            try:
                container = self.docker_client.containers.get(vm_instance.container_id)
                container.remove(force=True)
            except docker.errors.NotFound:
                pass  # Container already removed
            
            # Update status
            vm_instance.status = VMStatus.DELETED
            await self.db.commit()
            
            logger.info(f"Removed VM container {vm_instance.vm_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove VM container {vm_instance_id}: {e}")
            return False
    
    async def _cleanup_session_vms(self, session_id: uuid.UUID) -> bool:
        """Cleanup all VMs for a session"""
        
        try:
            # Get all VM instances for this session
            query = select(VMInstance).where(VMInstance.session_id == session_id)
            result = await self.db.execute(query)
            vm_instances = result.scalars().all()
            
            for vm_instance in vm_instances:
                await self.remove_vm_container(vm_instance.id)
            
            logger.info(f"Cleaned up {len(vm_instances)} VMs for session {session_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to cleanup VMs for session {session_id}: {e}")
            return False
    
    async def get_vm_status(self, vm_instance_id: uuid.UUID) -> Optional[Dict[str, Any]]:
        """Get VM container status and details"""
        
        try:
            # Get VM instance
            query = select(VMInstance).where(VMInstance.id == vm_instance_id)
            result = await self.db.execute(query)
            vm_instance = result.scalar_one_or_none()
            
            if not vm_instance:
                return None
            
            status_info = {
                "id": vm_instance.id,
                "name": vm_instance.vm_name,
                "type": vm_instance.vm_type,
                "status": vm_instance.status,
                "ip_address": vm_instance.ip_address,
                "created_at": vm_instance.created_at,
                "started_at": vm_instance.started_at
            }
            
            # Get container runtime status if available
            if vm_instance.container_id:
                try:
                    container = self.docker_client.containers.get(vm_instance.container_id)
                    container_status = container.status
                    
                    status_info.update({
                        "container_status": container_status,
                        "container_id": vm_instance.container_id[:12]  # Short ID
                    })
                    
                    # Get resource usage
                    stats = container.stats(stream=False)
                    if stats:
                        cpu_usage = self._calculate_cpu_usage(stats)
                        memory_usage = stats.get("memory_usage", {})
                        
                        status_info["resources"] = {
                            "cpu_percent": cpu_usage,
                            "memory_usage_mb": memory_usage.get("usage", 0) // (1024 * 1024),
                            "memory_limit_mb": memory_usage.get("limit", 0) // (1024 * 1024)
                        }
                        
                except docker.errors.NotFound:
                    status_info["container_status"] = "not_found"
                except Exception as e:
                    logger.warning(f"Failed to get container stats for VM {vm_instance_id}: {e}")
            
            return status_info
            
        except Exception as e:
            logger.error(f"Failed to get VM status {vm_instance_id}: {e}")
            return None
    
    def _calculate_cpu_usage(self, stats: Dict[str, Any]) -> float:
        """Calculate CPU usage percentage from Docker stats"""
        try:
            cpu_delta = stats["cpu_stats"]["cpu_usage"]["total_usage"] - \
                       stats["precpu_stats"]["cpu_usage"]["total_usage"]
            system_delta = stats["cpu_stats"]["system_cpu_usage"] - \
                          stats["precpu_stats"]["system_cpu_usage"]
            
            if system_delta > 0:
                cpu_percent = (cpu_delta / system_delta) * 100.0
                return round(cpu_percent, 2)
        except (KeyError, ZeroDivisionError):
            pass
        return 0.0
    
    async def _get_session_with_lab(self, session_id: uuid.UUID) -> Optional[LabSession]:
        """Get session with lab details"""
        query = select(LabSession).where(LabSession.id == session_id)
        result = await self.db.execute(query)
        return result.scalar_one_or_none()
    
    async def _get_lab_vm_configs(self, lab_id: uuid.UUID) -> List[Dict[str, Any]]:
        """Get VM configurations for a lab"""
        
        # For now, return mock configurations
        # In a real implementation, this would come from the lab's vm_templates field
        
        # Mock configuration for a basic penetration testing lab
        return [
            {
                "name": "kali-box",
                "type": "attack_box",
                "image": "cyberlab/kali-full:latest",
                "cpu_cores": 2,
                "ram_mb": 2048,
                "disk_gb": 20,
                "ports": [22, 80, 443],
                "environment": {
                    "DISPLAY": ":0",
                    "VNC_PASSWORD": "cyberlab123"
                },
                "capabilities": ["NET_ADMIN", "NET_RAW"]
            },
            {
                "name": "target-web",
                "type": "target",
                "image": "cyberlab/dvwa:latest",
                "cpu_cores": 1,
                "ram_mb": 512,
                "disk_gb": 10,
                "ports": [80, 443],
                "environment": {
                    "MYSQL_ROOT_PASSWORD": "password123",
                    "FLAG_USER": f"HTB{{{uuid.uuid4().hex[:16]}}}",
                    "FLAG_ROOT": f"HTB{{{uuid.uuid4().hex[:16]}}}"
                }
            }
        ]
    
    async def _update_session_resources(
        self, 
        session_id: uuid.UUID, 
        resources: Dict[str, int]
    ):
        """Update session with allocated resources"""
        
        query = select(LabSession).where(LabSession.id == session_id)
        result = await self.db.execute(query)
        session = result.scalar_one_or_none()
        
        if session:
            session.allocated_resources = {
                "total_cpu_cores": resources["cpu"],
                "total_ram_mb": resources["memory"],
                "storage_gb": resources["storage"],
                "network_bandwidth_mbps": 100,
                "container_count": len(await self._get_session_vms(session_id))
            }
            await self.db.commit()
    
    async def _get_session_vms(self, session_id: uuid.UUID) -> List[VMInstance]:
        """Get all VM instances for a session"""
        query = select(VMInstance).where(VMInstance.session_id == session_id)
        result = await self.db.execute(query)
        return result.scalars().all()
