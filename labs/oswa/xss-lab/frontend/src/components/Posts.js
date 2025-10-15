import React from 'react';
import { Container, Alert, Button } from 'react-bootstrap';
import { Link } from 'react-router-dom';

function Posts() {
  return (
    <Container>
      <Alert variant="info">
        <h4>Posts & Comments</h4>
        <p>Post and comment functionality is available in the Stored XSS challenge where you can practice persistent XSS attacks.</p>
        <Link to="/challenges/stored">
          <Button variant="primary">Go to Stored XSS Challenge</Button>
        </Link>
      </Alert>
    </Container>
  );
}

export default Posts;