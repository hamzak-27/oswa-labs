import React from 'react';
import { Container, Card, Alert } from 'react-bootstrap';
import { useAuth } from '../context/AuthContext';

function Admin() {
  const { user } = useAuth();
  
  if (!user?.isAdmin) {
    return (
      <Container>
        <Alert variant="danger">
          <h4>Access Denied</h4>
          <p>You need admin privileges to access this page.</p>
        </Alert>
      </Container>
    );
  }
  
  return (
    <Container>
      <Card className="bg-light">
        <Card.Header className="bg-danger text-white">
          <h4>Admin Panel</h4>
        </Card.Header>
        <Card.Body>
          <Alert variant="success">
            <h5>🎉 Congratulations!</h5>
            <p>You have successfully gained admin access! This demonstrates successful JWT privilege escalation.</p>
            <p><strong>Flag:</strong> <code>OSWA{JWT_ADMIN_ACCESS_GAINED}</code></p>
          </Alert>
          
          <h6>Admin Functions:</h6>
          <ul>
            <li>View sensitive data</li>
            <li>Manage users</li>
            <li>System configuration</li>
          </ul>
        </Card.Body>
      </Card>
    </Container>
  );
}

export default Admin;