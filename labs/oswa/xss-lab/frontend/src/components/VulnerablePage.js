import React from 'react';
import { Container, Row, Col, Card, Button } from 'react-bootstrap';
import { Link } from 'react-router-dom';

function VulnerablePage() {
  return (
    <Container>
      <Row>
        <Col md={4} className="mb-3">
          <Card>
            <Card.Header className="bg-danger text-white">Reflected XSS</Card.Header>
            <Card.Body>
              <Link to="/challenges/reflected">
                <Button variant="danger">Test Now</Button>
              </Link>
            </Card.Body>
          </Card>
        </Col>
        <Col md={4} className="mb-3">
          <Card>
            <Card.Header className="bg-warning">DOM XSS</Card.Header>
            <Card.Body>
              <Link to="/challenges/dom">
                <Button variant="warning">Test Now</Button>
              </Link>
            </Card.Body>
          </Card>
        </Col>
        <Col md={4} className="mb-3">
          <Card>
            <Card.Header className="bg-success text-white">Stored XSS</Card.Header>
            <Card.Body>
              <Link to="/challenges/stored">
                <Button variant="success">Test Now</Button>
              </Link>
            </Card.Body>
          </Card>
        </Col>
      </Row>
    </Container>
  );
}

export default VulnerablePage;