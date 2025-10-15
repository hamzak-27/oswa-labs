import React from 'react';
import { Container, Card } from 'react-bootstrap';

function Profile() {
  return (
    <Container>
      <Card>
        <Card.Header><h4>User Profile</h4></Card.Header>
        <Card.Body>
          <p>Profile functionality is for demonstration purposes only.</p>
        </Card.Body>
      </Card>
    </Container>
  );
}

export default Profile;