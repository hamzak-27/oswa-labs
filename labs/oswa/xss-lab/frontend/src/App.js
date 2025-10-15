import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { Container } from 'react-bootstrap';

// Components
import Navigation from './components/Navigation';
import Home from './components/Home';
import Login from './components/Login';
import Search from './components/Search';
import Posts from './components/Posts';
import Profile from './components/Profile';
import Comments from './components/Comments';
import VulnerablePage from './components/VulnerablePage';

// XSS Challenge Pages
import ReflectedXSS from './components/challenges/ReflectedXSS';
import StoredXSS from './components/challenges/StoredXSS';
import DOMXSS from './components/challenges/DOMXSS';

// Context
import { AuthProvider } from './context/AuthContext';

// Styles
import './App.css';

function App() {
  return (
    <AuthProvider>
      <Router>
        <div className="App">
          <Navigation />
          
          <Container fluid className="mt-4">
            <Routes>
              {/* Main Pages */}
              <Route path="/" element={<Home />} />
              <Route path="/login" element={<Login />} />
              <Route path="/search" element={<Search />} />
              <Route path="/posts" element={<Posts />} />
              <Route path="/posts/:id" element={<Comments />} />
              <Route path="/profile" element={<Profile />} />
              <Route path="/vulnerable" element={<VulnerablePage />} />
              
              {/* XSS Challenge Routes - Mirrors backend endpoints */}
              <Route path="/challenges/reflected" element={<ReflectedXSS />} />
              <Route path="/challenges/stored" element={<StoredXSS />} />
              <Route path="/challenges/dom" element={<DOMXSS />} />
              
              {/* Legacy routes for direct backend compatibility */}
              <Route path="/vulnerable/reflect" element={<ReflectedXSS />} />
              <Route path="/vulnerable/dom" element={<DOMXSS />} />
            </Routes>
          </Container>
          
          {/* Global XSS Detection */}
          <div id="global-flag-container" className="flag-container">
            🎯 XSS PAYLOAD EXECUTED SUCCESSFULLY!
          </div>
        </div>
      </Router>
    </AuthProvider>
  );
}

export default App;