import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { Container } from 'react-bootstrap';

// Components
import Navigation from './components/Navigation';
import Home from './components/Home';
import Login from './components/Login';
import Dashboard from './components/Dashboard';
import Profile from './components/Profile';
import Admin from './components/Admin';
import TokenView from './components/TokenView';

// Challenge Components
import NoneAlgorithm from './components/challenges/NoneAlgorithm';
import WeakSecret from './components/challenges/WeakSecret';
import AlgorithmConfusion from './components/challenges/AlgorithmConfusion';
import KidInjection from './components/challenges/KidInjection';

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
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/profile" element={<Profile />} />
              <Route path="/admin" element={<Admin />} />
              <Route path="/tokens" element={<TokenView />} />
              
              {/* JWT Challenge Routes */}
              <Route path="/challenges/none" element={<NoneAlgorithm />} />
              <Route path="/challenges/weak-secret" element={<WeakSecret />} />
              <Route path="/challenges/algorithm-confusion" element={<AlgorithmConfusion />} />
              <Route path="/challenges/kid-injection" element={<KidInjection />} />
            </Routes>
          </Container>
          
          {/* Global JWT Attack Success Indicator */}
          <div id="jwt-success-indicator" className="alert alert-success position-fixed top-0 end-0 m-3" style={{ display: 'none', zIndex: 9999 }}>
            <i className="fas fa-flag me-2"></i>
            <strong>JWT Attack Successful!</strong> Flag captured!
          </div>
        </div>
      </Router>
    </AuthProvider>
  );
}

export default App;