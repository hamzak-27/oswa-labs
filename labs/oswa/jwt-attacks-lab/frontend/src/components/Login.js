import React, { useState } from 'react';
import { Container, Row, Col, Card, Form, Button, Alert, Spinner } from 'react-bootstrap';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const result = await login(username, password);
      
      if (result.success) {
        navigate('/dashboard');
      } else {
        setError(result.error || 'Login failed');
      }
    } catch (err) {
      setError('An unexpected error occurred');
    } finally {
      setLoading(false);
    }
  };

  const fillCredentials = (user) => {
    if (user === 'alice') {
      setUsername('alice');
      setPassword('alice123');
    } else if (user === 'admin') {
      setUsername('admin');
      setPassword('admin123');
    }
  };

  return (
    <Container>
      <Row className="justify-content-center">
        <Col md={6} lg={5}>
          <Card className="shadow-lg bg-light">
            <Card.Header className="bg-primary text-white text-center">
              <h4 className="mb-0">
                <i className="fas fa-sign-in-alt me-2"></i>
                Login to JWT Lab
              </h4>
            </Card.Header>
            
            <Card.Body className="p-4">
              {error && (
                <Alert variant="danger" className="mb-3">
                  <i className="fas fa-exclamation-circle me-2"></i>
                  {error}
                </Alert>
              )}

              <Alert variant="info" className="mb-4">
                <h6><i className="fas fa-info-circle me-2"></i>Test Accounts</h6>
                <div className="d-flex gap-2 flex-wrap">
                  <Button 
                    variant="outline-primary" 
                    size="sm" 
                    onClick={() => fillCredentials('alice')}
                  >
                    <i className="fas fa-user me-1"></i>
                    alice / alice123
                  </Button>
                  <Button 
                    variant="outline-danger" 
                    size="sm" 
                    onClick={() => fillCredentials('admin')}
                  >
                    <i className="fas fa-user-shield me-1"></i>
                    admin / admin123
                  </Button>
                </div>
              </Alert>

              <Form onSubmit={handleSubmit}>
                <Form.Group className="mb-3">
                  <Form.Label>
                    <i className="fas fa-user me-1"></i>
                    Username
                  </Form.Label>
                  <Form.Control
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    required
                    disabled={loading}
                    placeholder="Enter username"
                    className="form-control-lg"
                  />
                </Form.Group>

                <Form.Group className="mb-4">
                  <Form.Label>
                    <i className="fas fa-lock me-1"></i>
                    Password
                  </Form.Label>
                  <Form.Control
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    disabled={loading}
                    placeholder="Enter password"
                    className="form-control-lg"
                  />
                </Form.Group>

                <Button 
                  variant="primary" 
                  type="submit" 
                  disabled={loading}
                  className="w-100 btn-lg"
                >
                  {loading ? (
                    <>
                      <Spinner
                        as="span"
                        animation="border"
                        size="sm"
                        role="status"
                        aria-hidden="true"
                        className="me-2"
                      />
                      Logging in...
                    </>
                  ) : (
                    <>
                      <i className="fas fa-sign-in-alt me-2"></i>
                      Login
                    </>
                  )}
                </Button>
              </Form>
            </Card.Body>
            
            <Card.Footer className="text-center text-muted">
              <small>
                <i className="fas fa-shield-alt me-1"></i>
                Educational purposes only - This is a vulnerable application
              </small>
            </Card.Footer>
          </Card>

          {/* Educational Information */}
          <Card className="mt-4 bg-light">
            <Card.Body>
              <h6><i className="fas fa-graduation-cap me-2"></i>What You'll Learn</h6>
              <ul className="small mb-0">
                <li><strong>JWT Structure:</strong> Header, Payload, and Signature components</li>
                <li><strong>Token Manipulation:</strong> How to modify and forge tokens</li>
                <li><strong>Algorithm Attacks:</strong> None algorithm, weak secrets, and confusion</li>
                <li><strong>Injection Techniques:</strong> Exploiting JWT parameters</li>
              </ul>
            </Card.Body>
          </Card>
        </Col>
      </Row>
    </Container>
  );
}

export default Login;