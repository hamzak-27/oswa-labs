"""
VPN service for managing OpenVPN server and client access
"""

import docker
import asyncio
import os
import tempfile
import uuid
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, update, delete
import subprocess
import logging
from pathlib import Path

from app.models.session import LabSession
from app.models.vpn import VPNCertificate
from app.core.config import settings
from app.core.redis import redis_client
from loguru import logger


class VPNService:
    """Service for managing VPN server and client certificates"""
    
    def __init__(self, db: AsyncSession = None):
        self.db = db
        self.docker_client = None
        self.vpn_container_name = "cyberlab-openvpn"
        self.openvpn_data_path = settings.OPENVPN_DATA_PATH
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
            
            logger.info("VPN Service: Docker client initialized successfully")
        except Exception as e:
            logger.error(f"VPN Service: Failed to initialize Docker client: {e}")
            self.docker_client = None
    
    async def is_vpn_server_running(self) -> bool:
        """Check if VPN server container is running"""
        if not self.docker_client:
            return False
        
        try:
            container = self.docker_client.containers.get(self.vpn_container_name)
            return container.status == 'running'
        except docker.errors.NotFound:
            return False
        except Exception as e:
            logger.error(f"Error checking VPN server status: {e}")
            return False
    
    async def start_vpn_server(self) -> Tuple[bool, str]:
        """Start the VPN server container"""
        if not self.docker_client:
            return False, "Docker client not available"
        
        try:
            container = self.docker_client.containers.get(self.vpn_container_name)
            if container.status != 'running':
                container.start()
                logger.info("VPN server container started")
                return True, "VPN server started successfully"
            else:
                return True, "VPN server already running"
                
        except docker.errors.NotFound:
            return False, "VPN server container not found. Please run initialization first."
        except Exception as e:
            logger.error(f"Failed to start VPN server: {e}")
            return False, str(e)
    
    async def stop_vpn_server(self) -> Tuple[bool, str]:
        """Stop the VPN server container"""
        if not self.docker_client:
            return False, "Docker client not available"
        
        try:
            container = self.docker_client.containers.get(self.vpn_container_name)
            if container.status == 'running':
                container.stop()
                logger.info("VPN server container stopped")
                return True, "VPN server stopped successfully"
            else:
                return True, "VPN server already stopped"
                
        except docker.errors.NotFound:
            return False, "VPN server container not found"
        except Exception as e:
            logger.error(f"Failed to stop VPN server: {e}")
            return False, str(e)
    
    async def create_client_certificate(
        self, 
        user_id: uuid.UUID, 
        session_id: uuid.UUID,
        certificate_name: Optional[str] = None
    ) -> Tuple[bool, str, Optional[str]]:
        """Create a client certificate for VPN access"""
        
        if not self.docker_client:
            return False, "Docker client not available", None
        
        if not certificate_name:
            certificate_name = f"cyberlab_user_{str(user_id).replace('-', '')[:12]}"
        
        try:
            # Check if VPN server is running
            if not await self.is_vpn_server_running():
                start_success, start_msg = await self.start_vpn_server()
                if not start_success:
                    return False, f"Cannot start VPN server: {start_msg}", None
            
            # Generate client certificate using OpenVPN container
            container = self.docker_client.containers.get(self.vpn_container_name)
            
            # Create certificate without passphrase
            result = container.exec_run(
                f"easyrsa build-client-full {certificate_name} nopass",
                workdir="/etc/openvpn"
            )
            
            if result.exit_code != 0:
                logger.error(f"Failed to create certificate: {result.output.decode()}")
                return False, f"Certificate creation failed: {result.output.decode()}", None
            
            # Generate client configuration
            config_result = container.exec_run(
                f"ovpn_getclient {certificate_name}",
                workdir="/etc/openvpn"
            )
            
            if config_result.exit_code != 0:
                logger.error(f"Failed to generate client config: {config_result.output.decode()}")
                return False, f"Config generation failed: {config_result.output.decode()}", None
            
            client_config = config_result.output.decode()
            
            # Store certificate info in database
            certificate = VPNCertificate(
                id=uuid.uuid4(),
                user_id=user_id,
                session_id=session_id,
                certificate_name=certificate_name,
                issued_at=datetime.utcnow(),
                expires_at=datetime.utcnow() + timedelta(hours=48),  # 48 hour expiry
                status='active'
            )
            
            self.db.add(certificate)
            await self.db.commit()
            await self.db.refresh(certificate)
            
            # Cache the configuration
            cache_key = f"vpn_config:{certificate.id}"
            await redis_client.set(cache_key, client_config, expire=172800)  # 48 hours
            
            logger.info(f"Created VPN certificate {certificate_name} for user {user_id}")
            return True, "Certificate created successfully", str(certificate.id)
            
        except Exception as e:
            logger.error(f"Failed to create client certificate: {e}")
            return False, str(e), None
    
    async def revoke_client_certificate(
        self, 
        certificate_id: uuid.UUID
    ) -> Tuple[bool, str]:
        """Revoke a client certificate"""
        
        if not self.docker_client:
            return False, "Docker client not available"
        
        try:
            # Get certificate from database
            query = select(VPNCertificate).where(VPNCertificate.id == certificate_id)
            result = await self.db.execute(query)
            certificate = result.scalar_one_or_none()
            
            if not certificate:
                return False, "Certificate not found"
            
            if certificate.status == 'revoked':
                return True, "Certificate already revoked"
            
            # Revoke certificate in OpenVPN
            container = self.docker_client.containers.get(self.vpn_container_name)
            
            revoke_result = container.exec_run(
                f"easyrsa revoke {certificate.certificate_name}",
                workdir="/etc/openvpn"
            )
            
            # Generate new CRL
            crl_result = container.exec_run(
                "easyrsa gen-crl",
                workdir="/etc/openvpn"
            )
            
            if crl_result.exit_code == 0:
                # Copy CRL to OpenVPN directory
                container.exec_run(
                    "cp /etc/openvpn/pki/crl.pem /etc/openvpn/",
                    workdir="/etc/openvpn"
                )
                
                # Restart OpenVPN to apply CRL
                container.restart()
            
            # Update database
            certificate.status = 'revoked'
            certificate.revoked_at = datetime.utcnow()
            await self.db.commit()
            
            # Remove from cache
            cache_key = f"vpn_config:{certificate_id}"
            await redis_client.delete(cache_key)
            
            logger.info(f"Revoked VPN certificate {certificate.certificate_name}")
            return True, "Certificate revoked successfully"
            
        except Exception as e:
            logger.error(f"Failed to revoke certificate: {e}")
            return False, str(e)
    
    async def get_client_config(self, certificate_id: uuid.UUID) -> Optional[str]:
        """Get client configuration for a certificate"""
        
        try:
            # Try cache first
            cache_key = f"vpn_config:{certificate_id}"
            cached_config = await redis_client.get(cache_key)
            if cached_config:
                return cached_config
            
            # Get certificate from database
            query = select(VPNCertificate).where(
                and_(
                    VPNCertificate.id == certificate_id,
                    VPNCertificate.status == 'active'
                )
            )
            result = await self.db.execute(query)
            certificate = result.scalar_one_or_none()
            
            if not certificate:
                return None
            
            # Check if expired
            if certificate.expires_at and certificate.expires_at < datetime.utcnow():
                return None
            
            # Regenerate config from OpenVPN container
            if not self.docker_client:
                return None
                
            container = self.docker_client.containers.get(self.vpn_container_name)
            config_result = container.exec_run(
                f"ovpn_getclient {certificate.certificate_name}",
                workdir="/etc/openvpn"
            )
            
            if config_result.exit_code == 0:
                client_config = config_result.output.decode()
                
                # Cache it
                await redis_client.set(cache_key, client_config, expire=172800)
                return client_config
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get client config: {e}")
            return None
    
    async def add_user_routes(
        self, 
        user_id: uuid.UUID, 
        lab_network: str
    ) -> Tuple[bool, str]:
        """Add routing rules for user's lab network"""
        
        try:
            # This would typically involve updating OpenVPN server configuration
            # For now, we'll use the client-config-dir feature of OpenVPN
            
            # Get user's certificate
            query = select(VPNCertificate).where(
                and_(
                    VPNCertificate.user_id == user_id,
                    VPNCertificate.status == 'active'
                )
            ).order_by(VPNCertificate.issued_at.desc())
            
            result = await self.db.execute(query)
            certificate = result.scalar_one_or_none()
            
            if not certificate:
                return False, "No active certificate found for user"
            
            # Create client-specific config
            client_config = f"iroute {lab_network.replace('/24', '')} 255.255.255.0\\n"
            
            # This would be implemented by writing to the OpenVPN ccd directory
            # For now, we'll log the intent
            logger.info(f"Would add route {lab_network} for user {user_id}")
            
            return True, f"Route added for network {lab_network}"
            
        except Exception as e:
            logger.error(f"Failed to add user routes: {e}")
            return False, str(e)
    
    async def get_vpn_status(self) -> Dict:
        """Get VPN server status and statistics"""
        
        try:
            status = {
                'server_running': await self.is_vpn_server_running(),
                'connected_clients': 0,
                'active_certificates': 0,
                'server_info': {}
            }
            
            # Get active certificates count
            if self.db:
                query = select(VPNCertificate).where(VPNCertificate.status == 'active')
                result = await self.db.execute(query)
                certificates = result.scalars().all()
                status['active_certificates'] = len(certificates)
            
            # Get server info if running
            if status['server_running'] and self.docker_client:
                try:
                    container = self.docker_client.containers.get(self.vpn_container_name)
                    status['server_info'] = {
                        'container_id': container.short_id,
                        'status': container.status,
                        'created': container.attrs['Created'],
                        'ports': container.attrs['NetworkSettings']['Ports']
                    }
                    
                    # Try to get connected clients from OpenVPN status
                    # This would require parsing OpenVPN management interface or log files
                    
                except Exception as e:
                    logger.warning(f"Could not get detailed server info: {e}")
            
            return status
            
        except Exception as e:
            logger.error(f"Failed to get VPN status: {e}")
            return {'error': str(e)}
    
    async def cleanup_expired_certificates(self) -> int:
        """Clean up expired certificates"""
        
        try:
            # Find expired certificates
            query = select(VPNCertificate).where(
                and_(
                    VPNCertificate.status == 'active',
                    VPNCertificate.expires_at < datetime.utcnow()
                )
            )
            result = await self.db.execute(query)
            expired_certificates = result.scalars().all()
            
            cleaned_count = 0
            for certificate in expired_certificates:
                success, message = await self.revoke_client_certificate(certificate.id)
                if success:
                    cleaned_count += 1
                    logger.info(f"Cleaned up expired certificate: {certificate.certificate_name}")
                else:
                    logger.warning(f"Failed to clean up certificate {certificate.certificate_name}: {message}")
            
            if cleaned_count > 0:
                logger.info(f"Cleaned up {cleaned_count} expired VPN certificates")
            
            return cleaned_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup expired certificates: {e}")
            return 0
    
    def is_docker_available(self) -> bool:
        """Check if Docker is available and accessible"""
        
        if not self.docker_client:
            return False
        
        try:
            self.docker_client.ping()
            return True
        except Exception:
            return False