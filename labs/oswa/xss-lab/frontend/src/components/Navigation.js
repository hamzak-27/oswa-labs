import React from 'react';
import { Navbar, Nav, Container, Badge } from 'react-bootstrap';
import { LinkContainer } from 'react-router-bootstrap';

function Navigation() {
  return (
    <Navbar bg="dark" variant="dark" expand="lg" sticky="top">
      <Container>
        <LinkContainer to="/">
          <Navbar.Brand>
            <i className="fas fa-shield-virus me-2"></i>
            SecureShare
            <Badge bg="danger" className="ms-2 fs-6">XSS LAB</Badge>
          </Navbar.Brand>
        </LinkContainer>
        
        <Navbar.Toggle aria-controls="basic-navbar-nav" />
        <Navbar.Collapse id="basic-navbar-nav">
          <Nav className="me-auto">
            <LinkContainer to="/">
              <Nav.Link><i className="fas fa-home me-1"></i>Home</Nav.Link>
            </LinkContainer>
            
            <LinkContainer to="/posts">
              <Nav.Link><i className="fas fa-comments me-1"></i>Posts</Nav.Link>
            </LinkContainer>
            
            <LinkContainer to="/search">
              <Nav.Link><i className="fas fa-search me-1"></i>Search</Nav.Link>
            </LinkContainer>
          </Nav>
          
          <Nav className="ms-auto">
            <Nav.Link href="#" className="text-warning">
              <i className="fas fa-bug me-1"></i>
              XSS Challenges
            </Nav.Link>
            
            <LinkContainer to="/login">
              <Nav.Link><i className="fas fa-sign-in-alt me-1"></i>Login</Nav.Link>
            </LinkContainer>
          </Nav>
        </Navbar.Collapse>
      </Container>
    </Navbar>
  );
}

export default Navigation;