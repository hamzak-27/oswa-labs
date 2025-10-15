import React, { useState, useEffect } from 'react';
import { Container, Row, Col, Card, Form, Button, Alert } from 'react-bootstrap';

function ReflectedXSS() {
  const [searchInput, setSearchInput] = useState('');
  const [searchResult, setSearchResult] = useState('');
  const [showFlag, setShowFlag] = useState(false);

  useEffect(() => {
    // Get search parameter from URL (simulating backend reflection)
    const urlParams = new URLSearchParams(window.location.search);
    const inputParam = urlParams.get('input');
    
    if (inputParam) {
      setSearchInput(inputParam);
      handleReflection(inputParam);
    }
  }, []);

  const handleReflection = (input) => {
    // VULNERABILITY: Direct HTML rendering without sanitization
    setSearchResult(input);
    
    // Check if XSS payload executed
    if (input.includes('<script>') || input.includes('javascript:') || input.includes('onerror=')) {
      // Simulate XSS execution detection
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
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    
    // Update URL to simulate GET request reflection
    const newUrl = `${window.location.pathname}?input=${encodeURIComponent(searchInput)}`;
    window.history.pushState({}, '', newUrl);
    
    handleReflection(searchInput);
  };

  const clearSearch = () => {
    setSearchInput('');
    setSearchResult('');
    setShowFlag(false);
    window.history.pushState({}, '', window.location.pathname);
  };

  return (
    <Container>
      <Row className="justify-content-center">
        <Col md={10}>
          <Card className="shadow">
            <Card.Header className="bg-danger text-white">
              <h4 className="mb-0">
                <i className="fas fa-search me-2"></i>
                Reflected XSS Challenge - User Search
              </h4>
            </Card.Header>
            
            <Card.Body>
              <Alert variant="warning" className="mb-4">
                <i className="fas fa-exclamation-triangle me-2"></i>
                <strong>Challenge:</strong> Find and exploit the reflected XSS vulnerability in the search functionality below.
              </Alert>

              {/* Vulnerable Search Form */}
              <Form onSubmit={handleSubmit} className="mb-4">
                <Form.Group className="mb-3">
                  <Form.Label><strong>Search Users:</strong></Form.Label>
                  <Form.Control
                    type="text"
                    placeholder="Enter username to search..."
                    value={searchInput}
                    onChange={(e) => setSearchInput(e.target.value)}
                    className="form-control-lg"
                  />
                  <Form.Text className="text-muted">
                    Try searching for: admin, alice, bob, or any username...
                  </Form.Text>
                </Form.Group>
                
                <div className="d-flex gap-2">
                  <Button variant="primary" type="submit" size="lg">
                    <i className="fas fa-search me-1"></i>
                    Search
                  </Button>
                  <Button variant="secondary" onClick={clearSearch} size="lg">
                    <i className="fas fa-times me-1"></i>
                    Clear
                  </Button>
                </div>
              </Form>

              {/* Vulnerable Search Results */}
              {searchResult && (
                <div className="vulnerable-content">
                  <h5>Search Results:</h5>
                  <p>You searched for: <strong 
                    // VULNERABILITY: Direct HTML injection
                    dangerouslySetInnerHTML={{ __html: searchResult }}
                  /></p>
                  
                  <div className="xss-payload">
                    <strong>Raw input reflected:</strong> {searchResult}
                  </div>
                  
                  <Alert variant="info" className="mt-3">
                    <i className="fas fa-info-circle me-2"></i>
                    Notice how your input is reflected directly in the page without proper encoding!
                  </Alert>
                </div>
              )}

              {/* Flag Reveal */}
              {showFlag && (
                <div className="flag-container" style={{ display: 'block' }}>
                  <h5><i className="fas fa-flag me-2"></i>FLAG CAPTURED!</h5>
                  <code>FLAG{R3FL3CT3D_XSS_M4ST3R}</code>
                  <p className="mt-2 mb-0">
                    <i className="fas fa-check-circle me-1"></i>
                    Congratulations! You successfully executed reflected XSS.
                  </p>
                </div>
              )}

              {/* Educational Information */}
              <Card className="mt-4 bg-light">
                <Card.Body>
                  <h6><i className="fas fa-lightbulb me-2"></i>Educational Notes:</h6>
                  <ul className="mb-0">
                    <li><strong>Vulnerability:</strong> User input is reflected directly in HTML without encoding</li>
                    <li><strong>Impact:</strong> Attackers can inject malicious scripts</li>
                    <li><strong>Example Payload:</strong> <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
                    <li><strong>Real-world Risk:</strong> Session hijacking, data theft, defacement</li>
                  </ul>
                </Card.Body>
              </Card>
            </Card.Body>
          </Card>
        </Col>
      </Row>
    </Container>
  );
}

export default ReflectedXSS;