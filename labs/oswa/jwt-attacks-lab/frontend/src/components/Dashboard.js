import React from 'react';
import { Container, Row, Col, Card, Button } from 'react-bootstrap';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

function Dashboard() {
  const { user, token } = useAuth();

  return (
    <Container>
      <Row className="justify-content-center">
        <Col md={10}>
          <h2 className="text-white mb-4">
            <i className="fas fa-tachometer-alt me-2"></i>
            Dashboard - Welcome {user?.username}!
          </h2>
          
          <Row>
            <Col md={4}>
              <Card className="mb-4 bg-light">
                <Card.Header className="bg-primary text-white">
                  <h5 className="mb-0">Profile</h5>
                </Card.Header>
                <Card.Body>
                  <p><strong>Username:</strong> {user?.username}</p>
                  <p><strong>Role:</strong> {user?.role}</p>
                  <p><strong>Admin:</strong> {user?.isAdmin ? 'Yes' : 'No'}</p>
                  <Link to="/profile">
                    <Button variant="primary">View Profile</Button>
                  </Link>
                </Card.Body>
              </Card>
            </Col>
            
            <Col md={4}>
              <Card className="mb-4 bg-light">
                <Card.Header className="bg-success text-white">
                  <h5 className="mb-0">JWT Token</h5>
                </Card.Header>
                <Card.Body>
                  <p>Your current JWT token is active and valid.</p>
                  <p><small>Token length: {token?.length || 0} characters</small></p>
                  <Link to="/tokens">
                    <Button variant="success">View Token</Button>
                  </Link>
                </Card.Body>
              </Card>
            </Col>
            
            <Col md={4}>
              <Card className="mb-4 bg-light">
                <Card.Header className="bg-warning text-dark">
                  <h5 className="mb-0">Challenges</h5>
                </Card.Header>
                <Card.Body>
                  <p>4 JWT attack challenges available.</p>
                  <p>Test your skills and capture flags!</p>
                  <Link to="/">
                    <Button variant="warning">Start Challenges</Button>
                  </Link>
                </Card.Body>
              </Card>
            </Col>
          </Row>
        </Col>
      </Row>
    </Container>
  );
}

export default Dashboard;