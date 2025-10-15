import React from 'react';
import { Container, Alert } from 'react-bootstrap';

function Search() {
  return (
    <Container>
      <Alert variant="info">
        <h4>Search Functionality</h4>
        <p>Search functionality is available in the XSS challenges. Visit the Reflected XSS challenge to test search-based vulnerabilities.</p>
      </Alert>
    </Container>
  );
}

export default Search;