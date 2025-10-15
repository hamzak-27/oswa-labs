import React from 'react';
import { Container, Row, Col, Card, Button, Alert, Badge } from 'react-bootstrap';
import { Link } from 'react-router-dom';

function Home() {
  return (
    <Container>
      <Row className="justify-content-center">
        <Col md={10}>
          <div className="text-center mb-5">
            <h1 className="display-4">
              <i className="fas fa-shield-virus text-danger me-3"></i>
              Welcome to SecureShare
            </h1>
            <p className="lead text-muted">
              OSWA XSS Laboratory - Educational Web Application Security Platform
            </p>
          </div>

          <Alert variant="warning" className="mb-4">
            <h5><i className="fas fa-exclamation-triangle me-2"></i>Educational Purpose Only</h5>
            <p className="mb-0">
              This application contains <strong>intentional security vulnerabilities</strong> designed for 
              learning Cross-Site Scripting (XSS) exploitation techniques. Do not deploy in production environments.
            </p>
          </Alert>

          <Row>
            <Col md={4} className="mb-4">
              <Card className="h-100 border-danger">
                <Card.Header className="bg-danger text-white">
                  <h5 className="mb-0">
                    <i className="fas fa-search me-2"></i>
                    Reflected XSS
                  </h5>
                </Card.Header>
                <Card.Body>
                  <p>
                    Practice exploiting reflected XSS vulnerabilities through search functionality 
                    where user input is immediately reflected in the response.
                  </p>
                  <Badge bg="warning" className="mb-2">Difficulty: Easy</Badge>
                  <br />
                  <Badge bg="info">Flag: FLAG{R3FL3CT3D_XSS_M4ST3R}</Badge>
                </Card.Body>
                <Card.Footer>
                  <Link to="/challenges/reflected">
                    <Button variant="danger" className="w-100">
                      Start Challenge
                    </Button>
                  </Link>
                </Card.Footer>
              </Card>
            </Col>

            <Col md={4} className="mb-4">
              <Card className="h-100 border-warning">
                <Card.Header className="bg-warning text-dark">
                  <h5 className="mb-0">
                    <i className="fas fa-code me-2"></i>
                    DOM XSS
                  </h5>
                </Card.Header>
                <Card.Body>
                  <p>
                    Exploit client-side DOM manipulation vulnerabilities using URL fragments 
                    and JavaScript DOM operations.
                  </p>
                  <Badge bg="warning" className="mb-2">Difficulty: Medium</Badge>
                  <br />
                  <Badge bg="info">Flag: FLAG{D0M_XSS_CSP_BYP4SS_L33T}</Badge>
                </Card.Body>
                <Card.Footer>
                  <Link to="/challenges/dom">
                    <Button variant="warning" className="w-100">
                      Start Challenge
                    </Button>
                  </Link>
                </Card.Footer>
              </Card>
            </Col>

            <Col md={4} className="mb-4">
              <Card className="h-100 border-success">
                <Card.Header className="bg-success text-white">
                  <h5 className="mb-0">
                    <i className="fas fa-comments me-2"></i>
                    Stored XSS
                  </h5>
                </Card.Header>
                <Card.Body>
                  <p>
                    Execute persistent stored XSS attacks through comment systems where 
                    malicious scripts are stored and executed for all users.
                  </p>
                  <Badge bg="danger" className="mb-2">Difficulty: Hard</Badge>
                  <br />
                  <Badge bg="info">Flag: FLAG{ST0R3D_XSS_C00K13_TH13F}</Badge>
                </Card.Body>
                <Card.Footer>
                  <Link to="/challenges/stored">
                    <Button variant="success" className="w-100">
                      Start Challenge
                    </Button>
                  </Link>
                </Card.Footer>
              </Card>
            </Col>
          </Row>

          <Card className="mt-5">
            <Card.Header>
              <h5 className="mb-0"><i className="fas fa-info-circle me-2"></i>Getting Started</h5>
            </Card.Header>
            <Card.Body>
              <Row>
                <Col md={6}>
                  <h6><i className="fas fa-play me-2"></i>How to Use This Lab:</h6>
                  <ol>
                    <li>Choose a challenge above</li>
                    <li>Read the challenge description carefully</li>
                    <li>Try to identify the vulnerability</li>
                    <li>Craft and execute XSS payloads</li>
                    <li>Capture the flag to complete the challenge</li>
                  </ol>
                </Col>
                <Col md={6}>
                  <h6><i className="fas fa-tools me-2"></i>Useful Tools:</h6>
                  <ul>
                    <li><strong>Browser DevTools:</strong> Inspect HTML and JavaScript</li>
                    <li><strong>Burp Suite:</strong> Intercept and modify requests</li>
                    <li><strong>URL Manipulation:</strong> Test different parameter values</li>
                    <li><strong>Payload Lists:</strong> Try various XSS vectors</li>
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