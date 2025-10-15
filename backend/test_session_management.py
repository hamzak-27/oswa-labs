#!/usr/bin/env python3
"""
Test script for session management functionality
Run this to verify that session management works correctly
"""

import asyncio
import asyncpg
import json
import requests
import uuid
from datetime import datetime

# Test configuration
API_BASE_URL = "http://localhost:8000/api/v1"
TEST_USERNAME = "admin"
TEST_PASSWORD = "Admin123!"
DATABASE_URL = "postgresql://cyberlab_user:cyberlab_dev_password@localhost:5432/cyberlab"

class SessionManagementTester:
    def __init__(self):
        self.auth_token = None
        self.user_id = None
        self.session_id = None
        self.lab_id = None
    
    def log(self, message):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
    
    def test_api_connection(self):
        """Test if API is accessible"""
        try:
            response = requests.get(f"{API_BASE_URL}/../health", timeout=5)
            if response.status_code == 200:
                self.log("✅ API is accessible")
                return True
            else:
                self.log(f"❌ API health check failed: {response.status_code}")
                return False
        except Exception as e:
            self.log(f"❌ Cannot connect to API: {e}")
            return False
    
    def authenticate(self):
        """Authenticate with the API"""
        try:
            response = requests.post(f"{API_BASE_URL}/auth/login", json={
                "username": TEST_USERNAME,
                "password": TEST_PASSWORD
            })
            
            if response.status_code == 200:
                data = response.json()
                self.auth_token = data["access_token"]
                self.user_id = data["user"]["id"]
                self.log(f"✅ Authenticated as {data['user']['username']}")
                return True
            else:
                self.log(f"❌ Authentication failed: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            self.log(f"❌ Authentication error: {e}")
            return False
    
    def get_headers(self):
        """Get authentication headers"""
        return {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json"
        }
    
    def get_available_lab(self):
        """Get the first available lab"""
        try:
            response = requests.get(f"{API_BASE_URL}/labs/", 
                                  headers=self.get_headers())
            
            if response.status_code == 200:
                data = response.json()
                if data["labs"]:
                    lab = data["labs"][0]
                    self.lab_id = lab["id"]
                    self.log(f"✅ Found lab: {lab['name']}")
                    return True
                else:
                    self.log("❌ No labs available")
                    return False
            else:
                self.log(f"❌ Failed to get labs: {response.status_code}")
                return False
        except Exception as e:
            self.log(f"❌ Error getting labs: {e}")
            return False
    
    def start_lab_session(self):
        """Start a lab session"""
        try:
            response = requests.post(f"{API_BASE_URL}/labs/{self.lab_id}/start", 
                                   params={
                                       "access_method": "web",
                                       "attack_box_os": "kali",
                                       "session_duration_hours": 2
                                   },
                                   headers=self.get_headers())
            
            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    self.session_id = data["session_id"]
                    self.log(f"✅ Lab session started: {self.session_id}")
                    self.log(f"   Network range: {data.get('network_range')}")
                    self.log(f"   Expires at: {data.get('expires_at')}")
                    return True
                else:
                    self.log(f"❌ Session start failed: {data.get('message')}")
                    return False
            else:
                self.log(f"❌ Failed to start session: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            self.log(f"❌ Error starting session: {e}")
            return False
    
    def get_session_details(self):
        """Get session details"""
        if not self.session_id:
            self.log("❌ No session ID available")
            return False
        
        try:
            response = requests.get(f"{API_BASE_URL}/sessions/{self.session_id}",
                                  headers=self.get_headers())
            
            if response.status_code == 200:
                data = response.json()
                self.log(f"✅ Session details retrieved")
                self.log(f"   Status: {data.get('status')}")
                self.log(f"   Lab: {data.get('lab_name')}")
                self.log(f"   Time remaining: {data.get('time_remaining_minutes')} minutes")
                self.log(f"   VM count: {len(data.get('vm_instances', []))}")
                return True
            else:
                self.log(f"❌ Failed to get session details: {response.status_code}")
                return False
        except Exception as e:
            self.log(f"❌ Error getting session details: {e}")
            return False
    
    def list_user_sessions(self):
        """List user's sessions"""
        try:
            response = requests.get(f"{API_BASE_URL}/sessions/",
                                  headers=self.get_headers())
            
            if response.status_code == 200:
                data = response.json()
                self.log(f"✅ User sessions retrieved")
                self.log(f"   Total: {data.get('total', 0)}")
                self.log(f"   Active: {data.get('active_count', 0)}")
                
                for session in data.get('sessions', [])[:3]:  # Show first 3
                    self.log(f"   - {session.get('lab_name')} ({session.get('status')})")
                return True
            else:
                self.log(f"❌ Failed to list sessions: {response.status_code}")
                return False
        except Exception as e:
            self.log(f"❌ Error listing sessions: {e}")
            return False
    
    def check_user_networks(self):
        """Check user's network information"""
        try:
            response = requests.get(f"{API_BASE_URL}/sessions/v1/networks",
                                  headers=self.get_headers())
            
            if response.status_code == 200:
                data = response.json()
                self.log(f"✅ Network information retrieved")
                self.log(f"   Total networks: {data.get('total_networks', 0)}")
                
                for network in data.get('networks', []):
                    self.log(f"   - {network.get('name')} ({network.get('subnet')})")
                return True
            else:
                self.log(f"❌ Failed to get network info: {response.status_code}")
                return False
        except Exception as e:
            self.log(f"❌ Error getting network info: {e}")
            return False
    
    def extend_session(self):
        """Extend the session duration"""
        if not self.session_id:
            self.log("❌ No session ID available for extension")
            return False
        
        try:
            response = requests.post(f"{API_BASE_URL}/sessions/v1/{self.session_id}/extend",
                                   json={"additional_hours": 1},
                                   headers=self.get_headers())
            
            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    self.log(f"✅ Session extended by 1 hour")
                    self.log(f"   New expiry: {data.get('new_expires_at')}")
                    return True
                else:
                    self.log(f"❌ Session extension failed: {data.get('message')}")
                    return False
            else:
                self.log(f"❌ Failed to extend session: {response.status_code}")
                return False
        except Exception as e:
            self.log(f"❌ Error extending session: {e}")
            return False
    
    def stop_session(self):
        """Stop the lab session"""
        if not self.session_id:
            self.log("❌ No session ID available for stopping")
            return False
        
        try:
            response = requests.post(f"{API_BASE_URL}/sessions/v1/{self.session_id}/stop",
                                   headers=self.get_headers())
            
            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    self.log(f"✅ Session stopped successfully")
                    return True
                else:
                    self.log(f"❌ Session stop failed: {data.get('message')}")
                    return False
            else:
                self.log(f"❌ Failed to stop session: {response.status_code}")
                return False
        except Exception as e:
            self.log(f"❌ Error stopping session: {e}")
            return False
    
    async def check_database_state(self):
        """Check database state directly"""
        try:
            conn = await asyncpg.connect(DATABASE_URL)
            
            # Check if tables exist
            tables = await conn.fetch("""
                SELECT table_name FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name IN ('lab_sessions', 'vm_instances', 'users', 'labs')
            """)
            
            self.log(f"✅ Database tables found: {[row['table_name'] for row in tables]}")
            
            # Check for sample data
            lab_count = await conn.fetchval("SELECT COUNT(*) FROM labs")
            user_count = await conn.fetchval("SELECT COUNT(*) FROM users") 
            session_count = await conn.fetchval("SELECT COUNT(*) FROM lab_sessions")
            
            self.log(f"✅ Database data: {lab_count} labs, {user_count} users, {session_count} sessions")
            
            await conn.close()
            return True
            
        except Exception as e:
            self.log(f"❌ Database check failed: {e}")
            return False
    
    async def run_full_test(self):
        """Run the complete test suite"""
        self.log("🚀 Starting Session Management Test Suite")
        self.log("=" * 50)
        
        tests = [
            ("API Connection", self.test_api_connection),
            ("Database State", self.check_database_state),
            ("Authentication", self.authenticate),
            ("Get Available Lab", self.get_available_lab),
            ("Start Lab Session", self.start_lab_session),
            ("Get Session Details", self.get_session_details),
            ("List User Sessions", self.list_user_sessions),
            ("Check User Networks", self.check_user_networks),
            ("Extend Session", self.extend_session),
            ("Stop Session", self.stop_session),
        ]
        
        passed = 0
        failed = 0
        
        for test_name, test_func in tests:
            self.log(f"\n🧪 Running: {test_name}")
            try:
                if asyncio.iscoroutinefunction(test_func):
                    result = await test_func()
                else:
                    result = test_func()
                
                if result:
                    passed += 1
                else:
                    failed += 1
                    
            except Exception as e:
                self.log(f"❌ Test {test_name} crashed: {e}")
                failed += 1
        
        self.log("\n" + "=" * 50)
        self.log(f"📊 Test Results: {passed} passed, {failed} failed")
        
        if failed == 0:
            self.log("🎉 All tests passed! Session management is working correctly.")
        else:
            self.log("⚠️ Some tests failed. Check the output above for details.")
        
        return failed == 0


if __name__ == "__main__":
    print("CyberLab Platform - Session Management Test")
    print("Make sure the API server and database are running before starting.")
    print()
    
    input("Press Enter to start testing...")
    
    tester = SessionManagementTester()
    success = asyncio.run(tester.run_full_test())
    
    if success:
        print("\n✅ Session management is ready for use!")
    else:
        print("\n❌ Session management needs fixes before use.")
