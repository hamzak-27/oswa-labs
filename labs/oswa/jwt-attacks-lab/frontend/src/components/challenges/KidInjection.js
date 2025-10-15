import React from 'react';
import { Container, Card, Alert, Badge } from 'react-bootstrap';

function KidInjection() {
  return (
    <Container>
      <Card className="bg-light">
        <Card.Header className="bg-success text-white">
          <h4><i className="fas fa-syringe me-2"></i>Key ID Injection Challenge</h4>
        </Card.Header>
        <Card.Body>
          <Alert variant="success">
            <h5>Challenge: JWT Kid Parameter Injection</h5>
            <p>Exploit the "kid" (Key ID) header parameter to perform path traversal attacks.</p>
            <Badge bg="success">Difficulty: Expert</Badge>
          </Alert>
          
          <Alert variant="warning">
            <h6>Implementation Status</h6>
            <p>This challenge component is a placeholder. Full implementation includes:</p>
            <ul>
              <li>JWT with kid parameter</li>
              <li>Path traversal injection</li>
              <li>File system access simulation</li>
              <li>Directory traversal interface</li>
              <li>Flag: <code>OSWA{JWT_KID_INJECTION_ATTACK}</code></li>
            </ul>
          </Alert>
        </Card.Body>
      </Card>
    </Container>
  );
}

export default KidInjection;