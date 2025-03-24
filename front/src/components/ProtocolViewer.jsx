import React, { useEffect, useState } from 'react';
import {
  DownloadIcon,
  ChevronDown,
  ChevronRight,
  Server,
  FileType,
  Activity,
  Database,
  Package,
  Eye,
  Grid,
  Code
} from 'lucide-react';

const BASE_URL = 'http://localhost:8383';

// A more elegant field display component
const FieldViewer = ({ field }) => {
  // Get icon based on field type
  const getFieldIcon = (type) => {
    switch (type.toLowerCase()) {
      case 'int':
      case 'float':
      case 'double':
        return <Activity className="text-blue-500" size={16} />;
      case 'string/code/data':
        return <Code className="text-purple-500" size={16} />;
      case 'char':
        return <FileType className="text-green-500" size={16} />;
      case 'bool':
        return <Grid className="text-amber-500" size={16} />;
      case 'bitfield':
        return <Database className="text-indigo-500" size={16} />;
      default:
        return <Package className="text-gray-500" size={16} />;
    }
  };

  // Get the display size based on type
  const getDisplaySize = () => {
    if (field.type === 'string/Code/Data') {
      return 'Dynamic';
    }
    return field.size;
  };

  return (
    <div className="p-4 mb-2 bg-white rounded-lg border border-gray-100 shadow-sm hover:shadow-md transition-all duration-200">
      <div className="flex items-center mb-3">
        {getFieldIcon(field.type)}
        <h3 className="ml-2 font-semibold text-gray-800">{field.name}</h3>
      </div>
      
      <div className="grid grid-cols-2 gap-3">
        <div className="bg-gray-50 p-2 rounded">
          <span className="text-xs text-gray-500 block mb-1">Type</span>
          <span className="font-medium text-gray-700">{field.type}</span>
        </div>
        
        <div className="bg-gray-50 p-2 rounded">
          <span className="text-xs text-gray-500 block mb-1">Size (bytes)</span>
          <span className="font-medium text-gray-700">{getDisplaySize()}</span>
        </div>
      </div>
    </div>
  );
};

// Simplified protocol field display
const ProtocolField = ({ name, data, fields }) => {
  // Get appropriate icon based on data type
  const getFieldIcon = (value) => {
    if (typeof value === 'boolean') {
      return value ? 
        <div className="w-3 h-3 rounded-full bg-emerald-500"></div> : 
        <div className="w-3 h-3 rounded-full bg-rose-500"></div>;
    }
    if (typeof value === 'number') {
      return <Activity className="text-blue-500" size={14} />;
    }
    if (typeof value === 'string' && value.length > 20) {
      return <Code className="text-purple-500" size={14} />;
    }
    return <Database className="text-gray-400" size={14} />;
  };

  const formatValue = (value) => {
    if (value === null) return 'null';
    if (typeof value === 'boolean') return value ? 'true' : 'false';
    if (typeof value === 'number') return value.toLocaleString();
    if (typeof value === 'string' && value.length > 50) {
      return value.substring(0, 47) + '...';
    }
    return value.toString();
  };
  
  // Group data into categories for cleaner display
  const groupData = (data) => {
    if (!data.field_type) return { main: data };
    
    const result = {
      main: {},
      metadata: {},
      technical: {}
    };
    
    Object.entries(data).forEach(([key, value]) => {
      if (value === null || key === '_id') return;
      
      // Sort keys into categories
      if (['field_type', 'value', 'size', 'name'].includes(key)) {
        result.main[key] = value;
      } else if (['offset', 'bit_offset', 'timestamp'].includes(key)) {
        result.technical[key] = value;
      } else {
        result.metadata[key] = value;
      }
    });
    
    return result;
  };
  
  // Check if this is a dynamically sized field
  const isDynamicallySized = () => {
    if (!data.field_type) return false;
    return data.field_type === 'string/Code/Data' || 
           (data.size === 0 && data.reference_field);
  };
  
  // Find the reference field that determines this field's size
  const findReferencedField = () => {
    if (!isDynamicallySized() || !data.reference_field) return null;
    return data.reference_field;
  };
  
  const referencedField = findReferencedField();
  const groupedData = groupData(data);
  const hasMainData = Object.keys(groupedData.main).length > 0;
  const hasMetadata = Object.keys(groupedData.metadata).length > 0;
  const hasTechnical = Object.keys(groupedData.technical).length > 0;

  return (
    <div className={`p-3 border rounded-lg bg-white shadow-sm mb-2 ${isDynamicallySized() ? 'border-indigo-200' : 'border-gray-100'}`}>
      <h4 className="font-medium text-gray-800 mb-2 flex items-center justify-between">
        <span>{name}</span>
        {isDynamicallySized() && (
          <div className="flex items-center bg-indigo-50 text-indigo-700 text-xs px-2 py-1 rounded-full">
            <span>Dynamic Size</span>
            {referencedField && (
              <span className="ml-1 font-semibold">• Size from: {referencedField}</span>
            )}
          </div>
        )}
      </h4>
      
      {hasMainData && (
        <div className="mb-2">
          {Object.entries(groupedData.main).map(([key, value]) => (
            <div key={key} className="flex items-center py-1 px-2 rounded mb-1 bg-gray-50">
              <div className="flex items-center mr-2">
                {getFieldIcon(value)}
              </div>
              <span className="text-xs text-gray-500 mr-2 w-20">
                {key.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ')}:
              </span>
              <span className="text-sm font-medium text-gray-700">
                {formatValue(value)}
              </span>
            </div>
          ))}
        </div>
      )}
      
      {(hasMetadata || hasTechnical) && (
        <div className="grid grid-cols-2 gap-2 mt-1">
          {Object.entries({...groupedData.metadata, ...groupedData.technical})
            .map(([key, value]) => (
              <div key={key} className="flex items-center bg-gray-50 rounded py-1 px-2">
                <span className="text-xs text-gray-500 mr-1 whitespace-nowrap overflow-hidden text-ellipsis">
                  {key.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ')}:
                </span>
                <span className="text-xs font-medium text-gray-700 ml-auto">
                  {formatValue(value)}
                </span>
              </div>
            ))}
        </div>
      )}
    </div>
  );
};

// Simplified IP Protocol Card
const IPProtocolCard = ({ ip, fields, name }) => {
  const [isExpanded, setIsExpanded] = useState(true);

  const handleDownload = () => {
    window.open(
      `${BASE_URL}/download-dissector?ip=${encodeURIComponent(ip)}&protocol=${name}`,
      '_blank'
    );
  };
  
  // Count dynamic fields
  const countDynamicFields = () => {
    return Object.values(fields).filter(field => 
      field.field_type === 'string/Code/Data' || 
      (field.size === 0 && field.reference_field)
    ).length;
  };
  
  const dynamicFieldCount = countDynamicFields();
  
  // Group fields by category for better organization
  const groupFieldsByCategory = (fields) => {
    const categories = {
      headers: {},
      data: {},
      metadata: {}
    };
    
    // Simple heuristic to categorize fields
    Object.entries(fields).forEach(([fieldName, fieldData]) => {
      if (fieldName.toLowerCase().includes('header') || 
          fieldName.toLowerCase().includes('type') || 
          fieldName.toLowerCase().includes('version')) {
        categories.headers[fieldName] = fieldData;
      } else if (fieldName.toLowerCase().includes('data') || 
                fieldName.toLowerCase().includes('payload') || 
                fieldName.toLowerCase().includes('content')) {
        categories.data[fieldName] = fieldData;
      } else {
        categories.metadata[fieldName] = fieldData;
      }
    });
    
    return categories;
  };
  
  const groupedFields = groupFieldsByCategory(fields);
  
  return (
    <div className="bg-white rounded-xl border border-gray-200 overflow-hidden shadow-sm hover:shadow-md transition-all duration-200">
      <div className="border-b border-gray-200 bg-gradient-to-r from-indigo-50 to-white">
        <div className="flex items-center justify-between p-4">
          <div
            className="flex items-center space-x-3 cursor-pointer flex-1"
            onClick={() => setIsExpanded(!isExpanded)}
          >
            {isExpanded ? (
              <ChevronDown className="text-indigo-400" />
            ) : (
              <ChevronRight className="text-indigo-400" />
            )}
            <div className="flex items-center space-x-2">
              <Server className="text-indigo-500" size={22} />
              <span className="font-semibold text-gray-800">{ip}</span>
            </div>
          </div>
          <div className="flex items-center space-x-4">
            <span className="px-3 py-1 bg-indigo-50 text-indigo-700 rounded-full text-xs font-medium">
              {Object.keys(fields).length} Fields
            </span>
            {dynamicFieldCount > 0 && (
              <span className="px-3 py-1 bg-purple-50 text-purple-700 rounded-full text-xs font-medium">
                {dynamicFieldCount} Dynamic
              </span>
            )}
            <button
              onClick={handleDownload}
              className="flex items-center space-x-1 px-3 py-1.5 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-all duration-200 shadow-sm"
            >
              <DownloadIcon size={16} />
              <span className="text-sm font-medium">Download</span>
            </button>
          </div>
        </div>
      </div>
      
      {isExpanded && (
        <div className="p-4 bg-gray-50">
          {/* Show categorized fields */}
          {Object.keys(groupedFields.headers).length > 0 && (
            <div className="mb-4">
              <h3 className="text-sm font-medium text-gray-500 mb-2 ml-1 flex items-center">
                <Database size={14} className="mr-1 text-indigo-400" />
                Headers
              </h3>
              <div className="space-y-1">
                {Object.entries(groupedFields.headers).map(([fieldName, fieldData]) => (
                  <ProtocolField key={fieldData._id || fieldName} name={fieldName} data={fieldData} />
                ))}
              </div>
            </div>
          )}
          
          {Object.keys(groupedFields.data).length > 0 && (
            <div className="mb-4">
              <h3 className="text-sm font-medium text-gray-500 mb-2 ml-1 flex items-center">
                <Code size={14} className="mr-1 text-indigo-400" />
                Data & Payload
              </h3>
              <div className="space-y-1">
                {Object.entries(groupedFields.data).map(([fieldName, fieldData]) => (
                  <ProtocolField key={fieldData._id || fieldName} name={fieldName} data={fieldData} />
                ))}
              </div>
            </div>
          )}
          
          {Object.keys(groupedFields.metadata).length > 0 && (
            <div>
              <h3 className="text-sm font-medium text-gray-500 mb-2 ml-1 flex items-center">
                <Activity size={14} className="mr-1 text-indigo-400" />
                Additional Fields
              </h3>
              <div className="space-y-1">
                {Object.entries(groupedFields.metadata).map(([fieldName, fieldData]) => (
                  <ProtocolField key={fieldData._id || fieldName} name={fieldName} data={fieldData} />
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// Redesigned Protocol Output Display
const ProtocolOutputDisplay = ({ dpi, name }) => {
  const handleGlobalDownload = () => {
    window.open(`${BASE_URL}/download-dissector?ip=Global&protocol=${name}`, '_blank');
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between pb-4 border-b border-gray-200">
        <h2 className="text-xl font-bold text-gray-800 flex items-center">
          <Eye className="mr-2 text-indigo-500" />
          Protocol Analysis Results
        </h2>
        <button
          onClick={handleGlobalDownload}
          className="flex items-center space-x-2 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-all duration-200 shadow-sm"
        >
          <DownloadIcon size={18} />
          <span>Download Global Dissector</span>
        </button>
      </div>
      {dpi.length > 0 ? (
        <div className="grid gap-6">
          {dpi.map((entry) => (
            <IPProtocolCard
              key={entry._id}
              ip={entry.ip}
              fields={entry.fields}
              name={name}
            />
          ))}
        </div>
      ) : (
        <div className="text-center py-8">
          <Server size={48} className="mx-auto text-gray-300 mb-4" />
          <p className="text-gray-500">No analysis data available yet</p>
        </div>
      )}
    </div>
  );
};

// Main Protocol Viewer Component
const ProtocolViewer = ({ protocolData }) => {
  const [protocol, setProtocol] = useState(protocolData || null);
  const [activeTab, setActiveTab] = useState('fields');

  useEffect(() => {
    if (!protocolData) {
      fetch(`${BASE_URL}/protocol`)
        .then((response) => response.json())
        .then((data) => setProtocol(data))
        .catch((error) => console.error('Error fetching protocol data:', error));
    }
  }, [protocolData]);

  if (!protocol) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-500 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading protocol data...</p>
        </div>
      </div>
    );
  }

  const { name, fields, files, dpi } = protocol;

  // Tab configuration
  const tabs = [
    { id: 'fields', label: 'Fields', icon: <Database size={18} /> },
    { id: 'files', label: 'Files', icon: <FileType size={18} /> },
    { id: 'analysis', label: 'Analysis', icon: <Eye size={18} /> },
  ];

  return (
    <div className="max-w-4xl mx-auto bg-white shadow-xl rounded-xl overflow-hidden">
      {/* Header */}
      <div className="bg-gradient-to-r from-indigo-600 to-purple-600 p-6">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-white mb-2">{name}</h1>
          <p className="text-indigo-100 text-sm">Protocol Configuration</p>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="border-b border-gray-200">
        <div className="flex px-6">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center py-4 px-4 mr-4 text-sm font-medium border-b-2 transition-all duration-200 ${
                activeTab === tab.id
                  ? 'border-indigo-500 text-indigo-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              <span className="mr-2">{tab.icon}</span>
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab Content */}
      <div className="p-6">
        {activeTab === 'fields' && (
          <div className="space-y-4">
            <div className="flex items-center mb-4">
              <Database className="text-indigo-500 mr-2" size={20} />
              <h2 className="text-xl font-semibold text-gray-800">Protocol Fields</h2>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {fields.map((field) => (
                <FieldViewer key={field._id} field={field} />
              ))}
            </div>
          </div>
        )}

        {activeTab === 'files' && (
          <div className="space-y-4">
            <div className="flex items-center mb-4">
              <FileType className="text-indigo-500 mr-2" size={20} />
              <h2 className="text-xl font-semibold text-gray-800">Uploaded Files</h2>
            </div>
            
            <div className="bg-gray-50 rounded-lg p-4 border border-gray-200">
              {files.length > 0 ? (
                <div className="space-y-2">
                  {files.map((file, index) => (
                    <div
                      key={index}
                      className="flex items-center p-3 bg-white border border-gray-100 rounded-lg shadow-sm"
                    >
                      <FileType className="text-indigo-400 mr-3" size={18} />
                      <span className="text-gray-700">{file}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-6">
                  <FileType className="mx-auto text-gray-300 mb-2" size={32} />
                  <p className="text-gray-500">No files available</p>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'analysis' && (
          <div className="space-y-4">
            {(!dpi || dpi.length === 0) ? (
              <div className="text-center py-8 bg-gray-50 rounded-lg border border-gray-200">
                <Activity className="mx-auto text-gray-300 mb-4" size={48} />
                <h3 className="text-gray-600 font-medium mb-2">No Analysis Data Available</h3>
                <p className="text-gray-500 text-sm">Run the protocol to generate analysis results.</p>
              </div>
            ) : (
              <ProtocolOutputDisplay dpi={dpi} name={name} />
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default ProtocolViewer;