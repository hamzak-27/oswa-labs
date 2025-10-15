"""
Network service for Docker network management and user isolation
"""

import docker
import ipaddress
from typing import Dict, List, Optional, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
import uuid
import asyncio
from datetime import datetime

from app.models.session import LabSession
from app.core.redis import redis_client
from loguru import logger


class NetworkService:
    """Service for managing Docker networks and user isolation"""
    
    def __init__(self, db: AsyncSession = None):
        self.db = db
        self.docker_client = None
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
            
            logger.info("Docker client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Docker client: {e}")
            self.docker_client = None
    
    async def create_user_network(
        self,
        user_id: uuid.UUID,
        session_id: uuid.UUID,
        network_range: str
    ) -> Tuple[bool, str]:
        """Create an isolated Docker network for a user session"""
        
        if not self.docker_client:
            return False, "Docker client not available"
        
        network_name = f"cyberlab_user_{str(user_id).replace('-', '')[:12]}"
        
        try:
            # Check if network already exists
            existing_networks = self.docker_client.networks.list(names=[network_name])
            if existing_networks:
                logger.info(f"Network {network_name} already exists, reusing")
                return True, network_name
            
            # Parse network range
            network = ipaddress.IPv4Network(network_range, strict=False)
            subnet = str(network)
            gateway = str(network.network_address + 1)
            
            # Create IPAM config for the network
            ipam_config = docker.types.IPAMConfig(
                pool_configs=[
                    docker.types.IPAMPool(
                        subnet=subnet,
                        gateway=gateway
                    )
                ]
            )
            
            # Create the network
            docker_network = self.docker_client.networks.create(
                name=network_name,
                driver="bridge",
                ipam=ipam_config,
                options={
                    "com.docker.network.bridge.enable_icc": "true",
                    "com.docker.network.bridge.enable_ip_masquerade": "true",
                    "com.docker.network.driver.mtu": "1500"
                },
                labels={
                    "cyberlab.user_id": str(user_id),
                    "cyberlab.session_id": str(session_id),
                    "cyberlab.network_type": "user_isolation",
                    "cyberlab.created_at": datetime.utcnow().isoformat()
                }
            )
            
            # Cache network info
            await self._cache_network_info(user_id, session_id, network_name, network_range)
            
            logger.info(f"Created Docker network {network_name} with range {network_range}")
            return True, network_name
            
        except Exception as e:
            logger.error(f"Failed to create network {network_name}: {e}")
            return False, str(e)
    
    async def remove_user_network(
        self,
        user_id: uuid.UUID,
        session_id: uuid.UUID = None,
        network_name: str = None
    ) -> bool:
        """Remove a user's Docker network"""
        
        if not self.docker_client:
            logger.warning("Docker client not available for network cleanup")
            return False
        
        if not network_name:
            network_name = f"cyberlab_user_{str(user_id).replace('-', '')[:12]}"
        
        try:
            # Get the network
            networks = self.docker_client.networks.list(names=[network_name])
            if not networks:
                logger.info(f"Network {network_name} not found, assuming already removed")
                return True
            
            network = networks[0]
            
            # Disconnect any containers still connected
            containers = network.attrs.get('Containers', {})
            for container_id in containers:
                try:
                    container = self.docker_client.containers.get(container_id)
                    network.disconnect(container, force=True)
                    logger.info(f"Disconnected container {container_id} from network {network_name}")
                except Exception as e:
                    logger.warning(f"Failed to disconnect container {container_id}: {e}")
            
            # Remove the network
            network.remove()
            
            # Remove from cache
            await self._remove_network_from_cache(user_id, session_id)
            
            logger.info(f"Removed Docker network {network_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove network {network_name}: {e}")
            return False
    
    async def get_available_ip_in_network(
        self,
        network_name: str,
        preferred_ip: str = None
    ) -> Optional[str]:
        """Get an available IP address in the specified network"""
        
        if not self.docker_client:
            return None
        
        try:
            networks = self.docker_client.networks.list(names=[network_name])
            if not networks:
                logger.error(f"Network {network_name} not found")
                return None
            
            network = networks[0]
            
            # Get network configuration
            ipam_config = network.attrs.get('IPAM', {})
            if not ipam_config.get('Config'):
                return None
            
            subnet_info = ipam_config['Config'][0]
            subnet = ipaddress.IPv4Network(subnet_info['Subnet'])
            gateway_ip = ipaddress.IPv4Address(subnet_info.get('Gateway', subnet.network_address + 1))
            
            # Get currently assigned IPs
            assigned_ips = set()
            assigned_ips.add(gateway_ip)  # Gateway is always assigned
            
            containers = network.attrs.get('Containers', {})
            for container_info in containers.values():
                container_ip = container_info.get('IPv4Address', '').split('/')[0]
                if container_ip:
                    assigned_ips.add(ipaddress.IPv4Address(container_ip))
            
            # Try preferred IP first
            if preferred_ip:
                try:
                    preferred = ipaddress.IPv4Address(preferred_ip)
                    if preferred in subnet and preferred not in assigned_ips:
                        return str(preferred)
                except ValueError:
                    pass
            
            # Find first available IP (starting from .10 to leave some room)
            for ip in subnet.hosts():
                if ip in assigned_ips:
                    continue
                if ip == gateway_ip:
                    continue
                if int(str(ip).split('.')[-1]) < 10:  # Reserve .1-.9 for infrastructure
                    continue
                    
                return str(ip)
            
            logger.warning(f"No available IPs found in network {network_name}")
            return None
            
        except Exception as e:
            logger.error(f"Failed to get available IP in network {network_name}: {e}")
            return None
    
    async def connect_container_to_network(
        self,
        container_id: str,
        network_name: str,
        ip_address: str = None,
        aliases: List[str] = None
    ) -> bool:
        """Connect a container to a network with specific IP"""
        
        if not self.docker_client:
            return False
        
        try:
            # Get container and network
            container = self.docker_client.containers.get(container_id)
            networks = self.docker_client.networks.list(names=[network_name])
            
            if not networks:
                logger.error(f"Network {network_name} not found")
                return False
            
            network = networks[0]
            
            # Prepare connection config
            connect_config = {}
            if ip_address:
                connect_config['ipv4_address'] = ip_address
            if aliases:
                connect_config['aliases'] = aliases
            
            # Connect container to network
            network.connect(container, **connect_config)
            
            logger.info(f"Connected container {container_id} to network {network_name}" +
                       (f" with IP {ip_address}" if ip_address else ""))
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect container {container_id} to network {network_name}: {e}")
            return False
    
    async def disconnect_container_from_network(
        self,
        container_id: str,
        network_name: str,
        force: bool = True
    ) -> bool:
        """Disconnect a container from a network"""
        
        if not self.docker_client:
            return False
        
        try:
            networks = self.docker_client.networks.list(names=[network_name])
            if not networks:
                return True  # Network doesn't exist, consider it successful
            
            network = networks[0]
            
            try:
                container = self.docker_client.containers.get(container_id)
                network.disconnect(container, force=force)
                logger.info(f"Disconnected container {container_id} from network {network_name}")
                return True
            except docker.errors.NotFound:
                # Container not found or not connected
                return True
                
        except Exception as e:
            logger.error(f"Failed to disconnect container {container_id} from network {network_name}: {e}")
            return False
    
    async def list_user_networks(self, user_id: uuid.UUID = None) -> List[Dict]:
        """List all CyberLab networks, optionally filtered by user"""
        
        if not self.docker_client:
            return []
        
        try:
            # Get all networks with CyberLab labels
            all_networks = self.docker_client.networks.list()
            cyberlab_networks = []
            
            for network in all_networks:
                labels = network.attrs.get('Labels', {})
                if 'cyberlab.user_id' in labels:
                    network_info = {
                        'id': network.id,
                        'name': network.name,
                        'user_id': labels.get('cyberlab.user_id'),
                        'session_id': labels.get('cyberlab.session_id'),
                        'created_at': labels.get('cyberlab.created_at'),
                        'subnet': None,
                        'container_count': len(network.attrs.get('Containers', {}))
                    }
                    
                    # Get subnet info
                    ipam_config = network.attrs.get('IPAM', {})
                    if ipam_config.get('Config'):
                        network_info['subnet'] = ipam_config['Config'][0].get('Subnet')
                    
                    # Filter by user if specified
                    if user_id is None or labels.get('cyberlab.user_id') == str(user_id):
                        cyberlab_networks.append(network_info)
            
            return cyberlab_networks
            
        except Exception as e:
            logger.error(f"Failed to list networks: {e}")
            return []
    
    async def cleanup_orphaned_networks(self, max_age_hours: int = 24) -> int:
        """Cleanup networks that are older than specified age and have no active sessions"""
        
        if not self.docker_client or not self.db:
            return 0
        
        cleaned_count = 0
        
        try:
            # Get all CyberLab networks
            networks = await self.list_user_networks()
            
            for network_info in networks:
                try:
                    # Check if network is old enough
                    if network_info['created_at']:
                        created_at = datetime.fromisoformat(network_info['created_at'].replace('Z', '+00:00'))
                        age_hours = (datetime.utcnow().replace(tzinfo=created_at.tzinfo) - created_at).total_seconds() / 3600
                        
                        if age_hours < max_age_hours:
                            continue
                    
                    # Check if there's an active session for this network
                    session_id = network_info['session_id']
                    if session_id:
                        query = select(LabSession).where(
                            and_(
                                LabSession.id == uuid.UUID(session_id),
                                LabSession.status.in_(['active', 'provisioning', 'paused'])
                            )
                        )
                        result = await self.db.execute(query)
                        active_session = result.scalar_one_or_none()
                        
                        if active_session:
                            continue  # Skip networks with active sessions
                    
                    # Remove orphaned network
                    user_id = uuid.UUID(network_info['user_id']) if network_info['user_id'] else None
                    session_uuid = uuid.UUID(session_id) if session_id else None
                    
                    if await self.remove_user_network(user_id, session_uuid, network_info['name']):
                        cleaned_count += 1
                        logger.info(f"Cleaned up orphaned network: {network_info['name']}")
                
                except Exception as e:
                    logger.error(f"Failed to cleanup network {network_info.get('name', 'unknown')}: {e}")
            
            if cleaned_count > 0:
                logger.info(f"Cleaned up {cleaned_count} orphaned networks")
            
            return cleaned_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup orphaned networks: {e}")
            return 0
    
    async def get_network_stats(self, network_name: str) -> Optional[Dict]:
        """Get statistics for a network"""
        
        if not self.docker_client:
            return None
        
        try:
            networks = self.docker_client.networks.list(names=[network_name])
            if not networks:
                return None
            
            network = networks[0]
            containers = network.attrs.get('Containers', {})
            
            # Get subnet info
            ipam_config = network.attrs.get('IPAM', {})
            subnet_info = None
            if ipam_config.get('Config'):
                subnet_info = ipam_config['Config'][0]
            
            # Count assigned IPs
            assigned_ips = len(containers)
            total_ips = 0
            if subnet_info:
                subnet = ipaddress.IPv4Network(subnet_info['Subnet'])
                total_ips = subnet.num_addresses - 2  # Subtract network and broadcast
            
            return {
                'network_name': network_name,
                'network_id': network.id,
                'container_count': len(containers),
                'assigned_ips': assigned_ips,
                'total_ips': total_ips,
                'subnet': subnet_info.get('Subnet') if subnet_info else None,
                'gateway': subnet_info.get('Gateway') if subnet_info else None,
                'containers': list(containers.keys())
            }
            
        except Exception as e:
            logger.error(f"Failed to get network stats for {network_name}: {e}")
            return None
    
    # Private helper methods
    
    async def _cache_network_info(
        self,
        user_id: uuid.UUID,
        session_id: uuid.UUID,
        network_name: str,
        network_range: str
    ):
        """Cache network information in Redis"""
        
        network_data = {
            'user_id': str(user_id),
            'session_id': str(session_id),
            'network_name': network_name,
            'network_range': network_range,
            'created_at': datetime.utcnow().isoformat()
        }
        
        cache_key = f"network:{network_name}"
        await redis_client.set(cache_key, network_data, expire=86400)  # 24 hours
        
        # Also cache by user for quick lookup
        user_networks_key = f"user_networks:{user_id}"
        await redis_client.set(user_networks_key, {network_name: network_data}, expire=86400)
    
    async def _remove_network_from_cache(
        self,
        user_id: uuid.UUID,
        session_id: uuid.UUID = None
    ):
        """Remove network information from cache"""
        
        network_name = f"cyberlab_user_{str(user_id).replace('-', '')[:12]}"
        
        # Remove main cache entry
        cache_key = f"network:{network_name}"
        await redis_client.delete(cache_key)
        
        # Remove from user networks cache
        user_networks_key = f"user_networks:{user_id}"
        await redis_client.delete(user_networks_key)
    
    def is_docker_available(self) -> bool:
        """Check if Docker is available and accessible"""
        
        if not self.docker_client:
            return False
        
        try:
            self.docker_client.ping()
            return True
        except Exception:
            return False
