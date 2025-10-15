import React from 'react';
import { Container, Alert, Button } from 'react-bootstrap';
import { Link } from 'react-router-dom';

function Comments() {
  return (
    <Container>
      <Alert variant="info">
        <h4>Comments System</h4>
        <p>Comment functionality with XSS vulnerabilities is available in the Stored XSS challenge.</p>
        <Link to="/challenges/stored">
          <Button variant="primary">Go to Stored XSS Challenge</Button>
        </Link>
      </Alert>
    </Container>
  );
}

export default Comments;