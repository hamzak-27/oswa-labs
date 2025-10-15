import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Card, CardHeader, CardContent } from './ui/card';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { Progress } from './ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs';
import { 
  Play, 
  Square, 
  RotateCcw, 
  Monitor, 
  Globe, 
  Server, 
  Users, 
  Eye,
  AlertCircle,
  CheckCircle,
  Clock,
  Zap
} from 'lucide-react';
import { Alert, AlertDescription } from './ui/alert';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const LabControlPanel = () => {
  const [labs, setLabs] = useState([]);
  const [selectedLab, setSelectedLab] = useState(null);
  const [labDetails, setLabDetails] = useState(null);
  const [labLogs, setLabLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [error, setError] = useState(null);

  // Fetch all labs on component mount
  useEffect(() => {
    fetchLabs();
    // Poll for status updates every 10 seconds
    const interval = setInterval(fetchLabs, 10000);
    return () => clearInterval(interval);
  }, []);

  // Fetch detailed info when a lab is selected
  useEffect(() => {
    if (selectedLab) {
      fetchLabDetails(selectedLab);
      fetchLabLogs(selectedLab);
    }
  }, [selectedLab]);

  const fetchLabs = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/api/labs`);
      setLabs(response.data);
      setError(null);
    } catch (error) {
      console.error('Failed to fetch labs:', error);
      setError('Failed to fetch lab information');
    } finally {
      setLoading(false);
    }
  };

  const fetchLabDetails = async (labId) => {
    try {
      const response = await axios.get(`${API_BASE_URL}/api/labs/${labId}`);
      setLabDetails(response.data);
    } catch (error) {
      console.error('Failed to fetch lab details:', error);
    }
  };

  const fetchLabLogs = async (labId) => {
    try {
      const response = await axios.get(`${API_BASE_URL}/api/labs/${labId}/logs`);
      setLabLogs(response.data.logs || []);
    } catch (error) {
      console.error('Failed to fetch lab logs:', error);
    }
  };

  const performLabAction = async (labId, action) => {
    setActionLoading(true);
    try {
      const response = await axios.post(`${API_BASE_URL}/api/labs/${labId}/${action}`);
      
      if (response.data.success) {
        // Refresh lab data
        await fetchLabs();
        if (selectedLab === labId) {
          await fetchLabDetails(labId);
        }
        setError(null);
      } else {
        setError(response.data.message || `Failed to ${action} lab`);
      }
    } catch (error) {
      console.error(`Failed to ${action} lab:`, error);
      setError(error.response?.data?.message || `Failed to ${action} lab`);
    } finally {
      setActionLoading(false);
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'running':
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'starting':
        return <Clock className="h-4 w-4 text-yellow-500" />;
      case 'stopped':
        return <AlertCircle className="h-4 w-4 text-red-500" />;
      default:
        return <AlertCircle className="h-4 w-4 text-gray-500" />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'running':
        return 'bg-green-500';
      case 'starting':
        return 'bg-yellow-500';
      case 'stopped':
        return 'bg-red-500';
      default:
        return 'bg-gray-500';
    }
  };

  const getDifficultyColor = (difficulty) => {
    switch (difficulty.toLowerCase()) {
      case 'easy':
        return 'bg-green-100 text-green-800';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800';
      case 'hard':
        return 'bg-red-100 text-red-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <Zap className="h-8 w-8 animate-spin text-blue-500 mx-auto mb-4" />
          <p className="text-gray-600">Loading lab environment...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-gray-900">Lab Environment Control</h2>
        <Badge variant="outline" className="px-3 py-1">
          <Server className="h-4 w-4 mr-1" />
          {labs.filter(lab => lab.status === 'running').length}/{labs.length} Running
        </Badge>
      </div>

      {error && (
        <Alert className="border-red-200 bg-red-50">
          <AlertCircle className="h-4 w-4 text-red-500" />
          <AlertDescription className="text-red-700">{error}</AlertDescription>
        </Alert>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Lab List */}
        <div className="lg:col-span-1">
          <Card>
            <CardHeader>
              <h3 className="text-lg font-semibold">Available Labs</h3>
            </CardHeader>
            <CardContent className="space-y-4">
              {labs.map((lab) => (
                <div
                  key={lab.id}
                  className={`p-4 border rounded-lg cursor-pointer transition-all ${
                    selectedLab === lab.id
                      ? 'border-blue-500 bg-blue-50'
                      : 'border-gray-200 hover:border-gray-300'
                  }`}
                  onClick={() => setSelectedLab(lab.id)}
                >
                  <div className="flex items-center justify-between mb-2">
                    <h4 className="font-medium">{lab.name}</h4>
                    {getStatusIcon(lab.status)}
                  </div>
                  
                  <div className="flex items-center justify-between text-sm text-gray-600 mb-2">
                    <Badge className={getDifficultyColor(lab.difficulty)}>
                      {lab.difficulty}
                    </Badge>
                    <span className={`px-2 py-1 rounded-full text-xs ${getStatusColor(lab.status)} text-white`}>
                      {lab.status}
                    </span>
                  </div>

                  <div className="text-sm text-gray-600 mb-2">
                    {lab.category} • {lab.flags}/{lab.totalFlags} flags
                  </div>

                  {lab.status === 'running' && lab.vpnIP && (
                    <div className="text-xs text-blue-600 font-mono bg-blue-50 p-2 rounded">
                      VPN Access: {lab.vpnIP}:{lab.vpnPort}
                    </div>
                  )}

                  <div className="mt-2">
                    <Progress 
                      value={(lab.flags / lab.totalFlags) * 100} 
                      className="h-2"
                    />
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>

        {/* Lab Details */}
        <div className="lg:col-span-2">
          {selectedLab && labDetails ? (
            <Tabs defaultValue="overview" className="w-full">
              <TabsList className="grid w-full grid-cols-4">
                <TabsTrigger value="overview">Overview</TabsTrigger>
                <TabsTrigger value="containers">Containers</TabsTrigger>
                <TabsTrigger value="logs">Logs</TabsTrigger>
                <TabsTrigger value="access">Access</TabsTrigger>
              </TabsList>

              <TabsContent value="overview">
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-4">
                    <div>
                      <h3 className="text-xl font-semibold">{labDetails.name}</h3>
                      <p className="text-gray-600 mt-1">{labDetails.description}</p>
                    </div>
                    <div className="flex space-x-2">
                      <Button
                        onClick={() => performLabAction(selectedLab, 'start')}
                        disabled={labDetails.status === 'running' || actionLoading}
                        className="bg-green-500 hover:bg-green-600"
                      >
                        <Play className="h-4 w-4 mr-1" />
                        Start
                      </Button>
                      <Button
                        onClick={() => performLabAction(selectedLab, 'stop')}
                        disabled={labDetails.status === 'stopped' || actionLoading}
                        variant="destructive"
                      >
                        <Square className="h-4 w-4 mr-1" />
                        Stop
                      </Button>
                      <Button
                        onClick={() => performLabAction(selectedLab, 'restart')}
                        disabled={labDetails.status === 'stopped' || actionLoading}
                        variant="outline"
                      >
                        <RotateCcw className="h-4 w-4 mr-1" />
                        Restart
                      </Button>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      <div className="text-center p-4 bg-gray-50 rounded-lg">
                        <div className="text-2xl font-bold text-blue-600">{labDetails.totalFlags}</div>
                        <div className="text-sm text-gray-600">Total Flags</div>
                      </div>
                      <div className="text-center p-4 bg-gray-50 rounded-lg">
                        <div className="text-2xl font-bold text-green-600">{labDetails.flags}</div>
                        <div className="text-sm text-gray-600">Captured</div>
                      </div>
                      <div className="text-center p-4 bg-gray-50 rounded-lg">
                        <div className="text-2xl font-bold text-purple-600">{labDetails.difficulty}</div>
                        <div className="text-sm text-gray-600">Difficulty</div>
                      </div>
                      <div className="text-center p-4 bg-gray-50 rounded-lg">
                        <div className="text-2xl font-bold text-orange-600">{labDetails.category}</div>
                        <div className="text-sm text-gray-600">Category</div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="containers">
                <Card>
                  <CardHeader>
                    <h3 className="text-lg font-semibold">Container Status</h3>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      {labDetails.containers && labDetails.containers.length > 0 ? (
                        labDetails.containers.map((container) => (
                          <div key={container.id} className="flex items-center justify-between p-4 border rounded-lg">
                            <div>
                              <h4 className="font-medium">{container.name}</h4>
                              <p className="text-sm text-gray-600">{container.status}</p>
                            </div>
                            <div className="text-right">
                              <Badge className={container.state === 'running' ? 'bg-green-500' : 'bg-red-500'}>
                                {container.state}
                              </Badge>
                              <div className="text-xs text-gray-500 mt-1">
                                ID: {container.id.slice(0, 12)}
                              </div>
                            </div>
                          </div>
                        ))
                      ) : (
                        <div className="text-center text-gray-500 py-8">
                          <Monitor className="h-12 w-12 mx-auto mb-4 opacity-50" />
                          <p>No containers running</p>
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="logs">
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between">
                    <h3 className="text-lg font-semibold">Container Logs</h3>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => fetchLabLogs(selectedLab)}
                    >
                      Refresh
                    </Button>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4 max-h-96 overflow-y-auto">
                      {labLogs && labLogs.length > 0 ? (
                        labLogs.map((logEntry, index) => (
                          <div key={index} className="border rounded-lg p-4">
                            <h4 className="font-medium mb-2">{logEntry.containerName}</h4>
                            <pre className="text-xs bg-gray-900 text-green-400 p-3 rounded overflow-x-auto">
                              {logEntry.logs || 'No logs available'}
                            </pre>
                          </div>
                        ))
                      ) : (
                        <div className="text-center text-gray-500 py-8">
                          <Eye className="h-12 w-12 mx-auto mb-4 opacity-50" />
                          <p>No logs available</p>
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="access">
                <Card>
                  <CardHeader>
                    <h3 className="text-lg font-semibold">Lab Access Information</h3>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {labDetails.status === 'running' ? (
                      <>
                        {labDetails.vpnIP && (
                          <div className="p-4 bg-blue-50 border border-blue-200 rounded-lg">
                            <h4 className="font-medium text-blue-800 mb-2 flex items-center">
                              <Globe className="h-4 w-4 mr-2" />
                              VPN Network Access
                            </h4>
                            <div className="space-y-2 text-sm">
                              <div>
                                <strong>Target IP:</strong>
                                <code className="ml-2 bg-blue-100 px-2 py-1 rounded">{labDetails.vpnIP}</code>
                              </div>
                              <div>
                                <strong>Target Port:</strong>
                                <code className="ml-2 bg-blue-100 px-2 py-1 rounded">{labDetails.vpnPort}</code>
                              </div>
                              <div className="text-blue-700 mt-2">
                                Connect to your VPN first, then access the lab at the IP above.
                              </div>
                            </div>
                          </div>
                        )}
                        
                        {labDetails.url && (
                          <div className="p-4 bg-green-50 border border-green-200 rounded-lg">
                            <h4 className="font-medium text-green-800 mb-2 flex items-center">
                              <Monitor className="h-4 w-4 mr-2" />
                              Development Access
                            </h4>
                            <div className="space-y-2 text-sm">
                              <div>
                                <strong>Direct URL:</strong>
                                <a 
                                  href={labDetails.url} 
                                  target="_blank" 
                                  rel="noopener noreferrer"
                                  className="ml-2 text-blue-600 hover:text-blue-800 underline"
                                >
                                  {labDetails.url}
                                </a>
                              </div>
                              <div className="text-green-700 mt-2">
                                This is for development purposes only. Use VPN access in production.
                              </div>
                            </div>
                          </div>
                        )}
                      </>
                    ) : (
                      <div className="text-center text-gray-500 py-8">
                        <Users className="h-12 w-12 mx-auto mb-4 opacity-50" />
                        <p>Lab must be running to show access information</p>
                        <Button 
                          className="mt-4 bg-green-500 hover:bg-green-600"
                          onClick={() => performLabAction(selectedLab, 'start')}
                          disabled={actionLoading}
                        >
                          <Play className="h-4 w-4 mr-2" />
                          Start Lab
                        </Button>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>
            </Tabs>
          ) : (
            <Card>
              <CardContent className="flex items-center justify-center h-64">
                <div className="text-center text-gray-500">
                  <Monitor className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>Select a lab to view details and control options</p>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
};

export default LabControlPanel;