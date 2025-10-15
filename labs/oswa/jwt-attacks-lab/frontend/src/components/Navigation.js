import React from 'react';
import { Navbar, Nav, Container, Button, Badge } from 'react-bootstrap';
import { LinkContainer } from 'react-router-bootstrap';
import { useAuth } from '../context/AuthContext';

function Navigation() {
  const { isAuthenticated, user, logout } = useAuth();

  return (
    <Navbar bg="dark" variant="dark" expand="lg" sticky="top">
      <Container>
        <LinkContainer to="/">
          <Navbar.Brand>
            <i className="fas fa-key me-2"></i>
            JWT Security Lab
          </Navbar.Brand>
        </LinkContainer>
        
        <Navbar.Toggle aria-controls="basic-navbar-nav" />
        <Navbar.Collapse id="basic-navbar-nav">
          <Nav className="me-auto">
            <LinkContainer to="/">
              <Nav.Link>
                <i className="fas fa-home me-1"></i>
                Home
              </Nav.Link>
            </LinkContainer>
            
            {isAuthenticated && (
              <>
                <LinkContainer to="/dashboard">
                  <Nav.Link>
                    <i className="fas fa-tachometer-alt me-1"></i>
                    Dashboard
                  </Nav.Link>
                </LinkContainer>
                
                <LinkContainer to="/profile">
                  <Nav.Link>
                    <i className="fas fa-user me-1"></i>
                    Profile
                  </Nav.Link>
                </LinkContainer>
                
                <LinkContainer to="/tokens">
                  <Nav.Link>
                    <i className="fas fa-code me-1"></i>
                    Token View
                  </Nav.Link>
                </LinkContainer>
                
                {user?.role === 'admin' && (
                  <LinkContainer to="/admin">
                    <Nav.Link>
                      <i className="fas fa-shield-alt me-1"></i>
                      Admin Panel
                    </Nav.Link>
                  </LinkContainer>
                )}
              </>
            )}
            
            {/* Challenge Menu */}
            <Nav className="ms-3 border-start border-secondary ps-3">
              <span className="navbar-text text-light me-2">
                <small>Challenges:</small>
              </span>
              <LinkContainer to="/challenges/none">
                <Nav.Link className="text-danger">
                  None Algorithm
                </Nav.Link>
              </LinkContainer>
              <LinkContainer to="/challenges/weak-secret">
                <Nav.Link className="text-warning">
                  Weak Secret
                </Nav.Link>
              </LinkContainer>
              <LinkContainer to="/challenges/algorithm-confusion">
                <Nav.Link className="text-info">
                  Algorithm Confusion
                </Nav.Link>
              </LinkContainer>
              <LinkContainer to="/challenges/kid-injection">
                <Nav.Link className="text-success">
                  Kid Injection
                </Nav.Link>
              </LinkContainer>
            </Nav>
          </Nav>
          
          <Nav>
            {isAuthenticated ? (
              <Nav className="align-items-center">
                <span className="navbar-text me-3">
                  Welcome, <strong>{user?.username || 'User'}</strong>
                  {user?.role === 'admin' && (
                    <Badge bg="danger" className="ms-1">Admin</Badge>
                  )}
                </span>
                <Button variant="outline-light" size="sm" onClick={logout}>
                  <i className="fas fa-sign-out-alt me-1"></i>
                  Logout
                </Button>
              </Nav>
            ) : (
              <LinkContainer to="/login">
                <Nav.Link>
                  <Button variant="outline-light" size="sm">
                    <i className="fas fa-sign-in-alt me-1"></i>
                    Login
                  </Button>
                </Nav.Link>
              </LinkContainer>
            )}
          </Nav>
        </Navbar.Collapse>
      </Container>
    </Navbar>
  );
}

export default Navigation;