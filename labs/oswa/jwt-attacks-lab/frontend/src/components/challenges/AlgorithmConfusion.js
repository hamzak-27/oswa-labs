import React from 'react';
import { Container, Card, Alert, Badge } from 'react-bootstrap';

function AlgorithmConfusion() {
  return (
    <Container>
      <Card className="bg-light">
        <Card.Header className="bg-info text-white">
          <h4><i className="fas fa-exchange-alt me-2"></i>Algorithm Confusion Challenge</h4>
        </Card.Header>
        <Card.Body>
          <Alert variant="info">
            <h5>Challenge: RS256 to HS256 Algorithm Confusion</h5>
            <p>Exploit algorithm confusion by changing RS256 to HS256 and using the public key as HMAC secret.</p>
            <Badge bg="danger">Difficulty: Hard</Badge>
          </Alert>
          
          <Alert variant="warning">
            <h6>Implementation Status</h6>
            <p>This challenge component is a placeholder. Full implementation includes:</p>
            <ul>
              <li>RS256 signed token</li>
              <li>Public key extraction</li>
              <li>Algorithm switching interface</li>
              <li>HMAC signing with public key</li>
              <li>Flag: <code>OSWA{JWT_ALGORITHM_CONFUSION}</code></li>
            </ul>
          </Alert>
        </Card.Body>
      </Card>
    </Container>
  );
}

export default AlgorithmConfusion;