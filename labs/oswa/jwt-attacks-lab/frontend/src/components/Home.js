import React from 'react';
import { Container, Row, Col, Card, Button, Alert, Badge } from 'react-bootstrap';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

function Home() {
  const { isAuthenticated } = useAuth();

  return (
    <Container>
      <Row className="justify-content-center">
        <Col md={10}>
          <div className="text-center mb-5">
            <h1 className="display-4 text-white">
              <i className="fas fa-key text-warning me-3"></i>
              JWT Security Laboratory
            </h1>
            <p className="lead text-light">
              OSWA JWT Attacks Lab - Educational Platform for JWT Exploitation Techniques
            </p>
          </div>

          <Alert variant="warning" className="mb-4">
            <h5><i className="fas fa-exclamation-triangle me-2"></i>Educational Purpose Only</h5>
            <p className="mb-0">
              This application contains <strong>intentional JWT vulnerabilities</strong> designed for 
              learning JSON Web Token exploitation techniques. Do not deploy in production environments.
            </p>
          </Alert>

          {!isAuthenticated && (
            <Alert variant="info" className="mb-4">
              <h5><i className="fas fa-info-circle me-2"></i>Getting Started</h5>
              <p className="mb-2">
                To access the full lab experience, please log in with one of these test accounts:
              </p>
              <ul className="mb-2">
                <li><strong>Regular User:</strong> alice / alice123</li>
                <li><strong>Admin User:</strong> admin / admin123</li>
              </ul>
              <Link to="/login">
                <Button variant="primary">
                  <i className="fas fa-sign-in-alt me-1"></i>
                  Login Now
                </Button>
              </Link>
            </Alert>
          )}

          <Row>
            <Col md={6} className="mb-4">
              <Card className="h-100 challenge-card none-algorithm bg-light">
                <Card.Header className="bg-danger text-white">
                  <h5 className="mb-0">
                    <i className="fas fa-ban me-2"></i>
                    None Algorithm Attack
                  </h5>
                </Card.Header>
                <Card.Body>
                  <p>
                    Exploit JWT tokens that accept the "none" algorithm, bypassing signature 
                    verification entirely. This allows complete token manipulation.
                  </p>
                  <Badge bg="danger" className="mb-2">Difficulty: Easy</Badge>
                  <br />
                  <Badge bg="info">Flag Available</Badge>
                  <div className="mt-3">
                    <strong>Learning Goals:</strong>
                    <ul className="small mt-2">
                      <li>JWT structure and components</li>
                      <li>Algorithm header manipulation</li>
                      <li>Signature bypass techniques</li>
                    </ul>
                  </div>
                </Card.Body>
                <Card.Footer>
                  <Link to="/challenges/none">
                    <Button variant="danger" className="w-100">
                      Start Challenge
                    </Button>
                  </Link>
                </Card.Footer>
              </Card>
            </Col>

            <Col md={6} className="mb-4">
              <Card className="h-100 challenge-card weak-secret bg-light">
                <Card.Header className="bg-warning text-dark">
                  <h5 className="mb-0">
                    <i className="fas fa-unlock me-2"></i>
                    Weak Secret Attack
                  </h5>
                </Card.Header>
                <Card.Body>
                  <p>
                    Crack JWT tokens signed with weak secrets using dictionary attacks 
                    and brute force techniques against HMAC signatures.
                  </p>
                  <Badge bg="warning" className="mb-2">Difficulty: Medium</Badge>
                  <br />
                  <Badge bg="info">Flag Available</Badge>
                  <div className="mt-3">
                    <strong>Learning Goals:</strong>
                    <ul className="small mt-2">
                      <li>HMAC signature verification</li>
                      <li>Secret strength importance</li>
                      <li>Dictionary and brute force attacks</li>
                    </ul>
                  </div>
                </Card.Body>
                <Card.Footer>
                  <Link to="/challenges/weak-secret">
                    <Button variant="warning" className="w-100">
                      Start Challenge
                    </Button>
                  </Link>
                </Card.Footer>
              </Card>
            </Col>

            <Col md={6} className="mb-4">
              <Card className="h-100 challenge-card algorithm-confusion bg-light">
                <Card.Header className="bg-info text-white">
                  <h5 className="mb-0">
                    <i className="fas fa-exchange-alt me-2"></i>
                    Algorithm Confusion
                  </h5>
                </Card.Header>
                <Card.Body>
                  <p>
                    Exploit systems that accept multiple algorithms by changing RS256 to HS256, 
                    using the public key as the HMAC secret.
                  </p>
                  <Badge bg="danger" className="mb-2">Difficulty: Hard</Badge>
                  <br />
                  <Badge bg="info">Flag Available</Badge>
                  <div className="mt-3">
                    <strong>Learning Goals:</strong>
                    <ul className="small mt-2">
                      <li>RSA vs HMAC algorithms</li>
                      <li>Public key as symmetric secret</li>
                      <li>Algorithm switching attacks</li>
                    </ul>
                  </div>
                </Card.Body>
                <Card.Footer>
                  <Link to="/challenges/algorithm-confusion">
                    <Button variant="info" className="w-100">
                      Start Challenge
                    </Button>
                  </Link>
                </Card.Footer>
              </Card>
            </Col>

            <Col md={6} className="mb-4">
              <Card className="h-100 challenge-card kid-injection bg-light">
                <Card.Header className="bg-success text-white">
                  <h5 className="mb-0">
                    <i className="fas fa-syringe me-2"></i>
                    Key ID Injection
                  </h5>
                </Card.Header>
                <Card.Body>
                  <p>
                    Exploit the "kid" (Key ID) header parameter to perform path traversal 
                    attacks and directory traversal for arbitrary file access.
                  </p>
                  <Badge bg="success" className="mb-2">Difficulty: Expert</Badge>
                  <br />
                  <Badge bg="info">Flag Available</Badge>
                  <div className="mt-3">
                    <strong>Learning Goals:</strong>
                    <ul className="small mt-2">
                      <li>JWT header manipulation</li>
                      <li>Path traversal attacks</li>
                      <li>File system access via JWT</li>
                    </ul>
                  </div>
                </Card.Body>
                <Card.Footer>
                  <Link to="/challenges/kid-injection">
                    <Button variant="success" className="w-100">
                      Start Challenge
                    </Button>
                  </Link>
                </Card.Footer>
              </Card>
            </Col>
          </Row>

          <Card className="mt-5 bg-light">
            <Card.Header>
              <h5 className="mb-0"><i className="fas fa-info-circle me-2"></i>How to Use This Lab</h5>
            </Card.Header>
            <Card.Body>
              <Row>
                <Col md={6}>
                  <h6><i className="fas fa-play me-2"></i>Getting Started:</h6>
                  <ol>
                    <li>Login with test credentials (alice/alice123 or admin/admin123)</li>
                    <li>Choose a challenge from the cards above</li>
                    <li>Read the vulnerability description</li>
                    <li>Use the provided tools and techniques</li>
                    <li>Capture flags by successfully exploiting JWTs</li>
                  </ol>
                </Col>
                <Col md={6}>
                  <h6><i className="fas fa-tools me-2"></i>Useful Tools:</h6>
                  <ul>
                    <li><strong>JWT.io:</strong> Online JWT decoder and debugger</li>
                    <li><strong>Burp Suite:</strong> Intercept and modify requests</li>
                    <li><strong>John the Ripper:</strong> JWT secret cracking</li>
                    <li><strong>Custom Scripts:</strong> Python/Node.js for automation</li>
                    <li><strong>Browser DevTools:</strong> Inspect tokens and storage</li>
                  </ul>
                </Col>
              </Row>
            </Card.Body>
          </Card>
        </Col>
      </Row>
    </Container>
  );
}

export default Home;