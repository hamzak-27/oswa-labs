import React from 'react';
import { Container, Card } from 'react-bootstrap';
import { useAuth } from '../context/AuthContext';

function Profile() {
  const { user } = useAuth();
  
  return (
    <Container>
      <Card className="bg-light">
        <Card.Header><h4>User Profile</h4></Card.Header>
        <Card.Body>
          <p><strong>Username:</strong> {user?.username}</p>
          <p><strong>Role:</strong> {user?.role}</p>
          <p><strong>Admin:</strong> {user?.isAdmin ? 'Yes' : 'No'}</p>
        </Card.Body>
      </Card>
    </Container>
  );
}

export default Profile;