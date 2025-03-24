import React, { useState, useEffect } from 'react';
import {
  PlusIcon,
  TrashIcon,
  UploadIcon,
  SaveIcon,
  DownloadIcon,
  PlayIcon,
  ChevronDown,
  ChevronRight,
  Server,
} from 'lucide-react';

const DEFAULT_FIELD = { name: '', size: '4', type: 'int', referenceField: '' };
const BASE_URL = 'http://localhost:8383';

// Field Editor Component
const FieldEditor = ({ field, onFieldChange, onRemove, fields, index }) => {
  const FIELD_TYPE_CONFIGS = [
    { type: 'int', size: 4 },
    { type: 'float', size: 4 },
    { type: 'char', size: 1 },
    { type: 'string/Code/Data', size: 0 },
    { type: 'fixed-string', size: null }, // New fixed-sized string type
    { type: 'bitfield', size: null },
    { type: 'double', size: 8 },
    { type: 'bool', size: 1 },
    { type: 'long', size: 8},
    { type: 'short', size: 2},
    { type: 'custom', size: null },
    
  ];

  const handleTypeChange = (value) => {
    const selectedType = FIELD_TYPE_CONFIGS.find((option) => option.type === value);
    onFieldChange('type', value);
    
    if (selectedType && selectedType.size !== null) {
      onFieldChange('size', selectedType.size.toString());
    } else if (value === 'fixed-string') {
      // Set a default size for fixed-string type
      onFieldChange('size', '');
    } else {
      onFieldChange('size', '');
    }
    
    // Clear reference field if changing away from string/Code/Data
    if (value !== 'string/Code/Data') {
      onFieldChange('referenceField', '');
    }
  };

  // Get available fields for reference (excluding the current field)
  const availableReferenceFields = fields
    .filter(f => 
      f.name !== field.name && 
      f.name.trim() !== ''
    )
    .map(f => f.name);

  // Set a default reference field if none is selected and options are available
  React.useEffect(() => {
    if (field.type === 'string/Code/Data' && !field.referenceField && availableReferenceFields.length > 0) {
      onFieldChange('referenceField', availableReferenceFields[0]);
    }
  }, [field.type, field.referenceField, availableReferenceFields, onFieldChange]);

  return (
    <div className="flex flex-col md:flex-row items-start md:items-center space-y-4 md:space-y-0 md:space-x-4 mb-3 p-3 bg-gray-100 rounded-lg shadow-sm">
      <div className="flex-1 w-full">
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Field Name
        </label>
        <input
          value={field.name}
          onChange={(e) => onFieldChange('name', e.target.value)}
          className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          placeholder="Enter field name"
        />
      </div>

      <div className="w-full md:w-1/4">
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Field Type
        </label>
        <select
          value={field.type}
          onChange={(e) => handleTypeChange(e.target.value)}
          className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          {FIELD_TYPE_CONFIGS.map((option) => (
            <option key={option.type} value={option.type}>
              {option.type}
            </option>
          ))}
        </select>
      </div>

      <div className="w-full md:w-1/4">
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Field Size
        </label>
        <input
          value={field.type === 'string/Code/Data' ? 'undefined' : field.size}
          onChange={(e) => onFieldChange('size', e.target.value)}
          className={`w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 ${
            field.type === 'custom' || field.type === 'fixed-string' || field.type==='bitfield' ? 'focus:ring-blue-500' : 'bg-gray-100'
          }`}
          placeholder="Enter byte size"
          disabled={field.type !== 'custom' && field.type !== 'fixed-string' && field.type !== 'bitfield'}
        />
      </div>

      {field.type === 'string/Code/Data' && (
        <div className="w-full md:w-1/4">
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Length Field
          </label>
          <select
            value={field.referenceField}
            onChange={(e) => onFieldChange('referenceField', e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="">Select length field</option>
            {availableReferenceFields.map((fieldName) => (
              <option key={fieldName} value={fieldName}>
                {fieldName}
              </option>
            ))}
          </select>
        </div>
      )}

      <button
        onClick={onRemove}
        className="mt-6 md:mt-0 p-2 bg-red-500 text-white rounded-full hover:bg-red-600 transition-colors"
        title="Remove Field"
      >
        <TrashIcon size={20} />
      </button>
    </div>
  );
};

// Protocol Field Component
const ProtocolField = ({ name, data }) => {
  const getValueColor = (value) => {
    if (typeof value === 'boolean') {
      return value ? 'text-emerald-600' : 'text-rose-600';
    }
    return 'text-slate-700';
  };

  const formatValue = (value) => {
    if (value === null) return 'null';
    if (typeof value === 'boolean') return value ? 'true' : 'false';
    return value.toString();
  };

  return (
    <div className="py-2 px-4 hover:bg-slate-50 transition-colors">
      <div className="flex items-start">
        <span className="text-sm font-medium text-slate-600 w-40">{name}</span>
        <div className="flex-1">
          {typeof data === 'object' ? (
            <div className="grid grid-cols-2 gap-2">
              {Object.entries(data).map(([key, value]) => (
                <div key={key} className="flex items-center space-x-2">
                  <span className="text-sm text-slate-400">{key}:</span>
                  <span className={`text-sm font-medium ${getValueColor(value)}`}>
                    {formatValue(value)}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <span className={`text-sm font-medium ${getValueColor(data)}`}>
              {formatValue(data)}
            </span>
          )}
        </div>
      </div>
    </div>
  );
};

// IP Protocol Card Component
const IPProtocolCard = ({ ip, data, onDownload }) => {
  const [isExpanded, setIsExpanded] = React.useState(true);

  return (
    <div className="bg-white rounded-lg border border-slate-200 overflow-hidden">
      <div className="border-b border-slate-200">
        <div className="flex items-center justify-between p-4">
          <div 
            className="flex items-center space-x-3 cursor-pointer flex-1"
            onClick={() => setIsExpanded(!isExpanded)}
          >
            {isExpanded ? 
              <ChevronDown className="text-slate-400" /> : 
              <ChevronRight className="text-slate-400" />
            }
            <div className="flex items-center space-x-2">
              <Server className="text-indigo-500" size={20} />
              <span className="font-semibold text-slate-700">{ip}</span>
            </div>
          </div>
          <div className="flex items-center space-x-4">
            <span className="px-2.5 py-1 bg-indigo-50 text-indigo-700 rounded-full text-xs font-medium">
              {Object.keys(data).length} Fields
            </span>
            <button
              onClick={() => onDownload(ip)}
              className="flex items-center space-x-1 px-3 py-1.5 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 transition-colors"
            >
              <DownloadIcon size={16} />
              <span className="text-sm font-medium">Download</span>
            </button>
          </div>
        </div>
      </div>
      {isExpanded && (
        <div className="divide-y divide-slate-100">
          {Object.entries(data).map(([fieldName, fieldData]) => (
            <ProtocolField key={fieldName} name={fieldName} data={fieldData} />
          ))}
        </div>
      )}
    </div>
  );
};

// Protocol Output Display Component
const ProtocolOutputDisplay = ({ output, onDownload }) => {
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-bold text-slate-800">Protocol Analysis Results</h2>
        <button
          onClick={() => onDownload('global')}
          className="flex items-center space-x-2 px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 transition-colors"
        >
          <DownloadIcon size={18} />
          <span>Download Global Dissector</span>
        </button>
      </div>
      <div className="grid gap-4">
        {Object.entries(output).map(([ip, data]) => (
          <IPProtocolCard 
            key={ip} 
            ip={ip} 
            data={data} 
            onDownload={onDownload}
          />
        ))}
      </div>
    </div>
  );
};

// Main Protocol Editor Component
const ProtocolEditor = () => {
  const [protocolName, setProtocolName] = useState('');
  const [fields, setFields] = useState([DEFAULT_FIELD]);
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [output, setOutput] = useState({});
  const [loading, setLoading] = useState(false);
  const [pcapUploaded, setPcapUploaded] = useState(false);
  const [protocolRuned, setProtocolRuned] = useState(false);

  const isDissectorReady = pcapUploaded && protocolRuned;
  const canSave = isDissectorReady && Object.keys(output).length > 0 && protocolName.trim() !== '';

  const handleFieldChange = (index, fieldKey, value) => {
    setFields((prevFields) =>
      prevFields.map((f, i) =>
        i === index ? { ...f, [fieldKey]: value } : f
      )
    );
  };

  const addField = () => {
    setFields((prevFields) => [...prevFields, { ...DEFAULT_FIELD }]);
  };

  const removeField = (index) => {
    setFields((prevFields) => prevFields.filter((_, i) => i !== index));
  };

  const validateFields = () => {
    if (protocolName.trim() === '') {
      alert('Protocol name is required');
      return false;
    }

    for (let i = 0; i < fields.length; i++) {
      const field = fields[i];
      
      if (field.name.trim() === '') {
        alert(`Field ${i + 1} requires a name`);
        return false;
      }

      if (field.type === 'string/Code/Data') {
        if (!field.referenceField) {
          alert(`String/Code/Data field "${field.name}" requires a length field`);
          return false;
        }
        
        // Verify the referenced field exists
        const refFieldIndex = fields.findIndex(f => f.name === field.referenceField);
        if (refFieldIndex === -1) {
          alert(`Length field for "${field.name}" does not exist`);
          return false;
        }
      }

      if ((field.type === 'custom' || field.type === 'fixed-string') && 
          (!field.size || isNaN(parseInt(field.size)) || parseInt(field.size) <= 0)) {
        alert(`${field.type === 'custom' ? 'Custom' : 'Fixed String'} field "${field.name}" requires a valid size`);
        return false;
      }
    }

    return true;
  };

  const handleFileChange = (event) => {
    setSelectedFiles(Array.from(event.target.files));
  };

  const uploadFiles = async () => {
    if (!selectedFiles.length) {
      alert('Please select at least one PCAP file before uploading.');
      return;
    }

    setLoading(true);
    const formData = new FormData();
    selectedFiles.forEach((file) => {
      formData.append('pcapFile', file);
    });

    try {
      const response = await fetch(`${BASE_URL}/upload`, {
        method: 'POST',
        body: formData,
      });

      if (response.ok) {
        alert('PCAP files uploaded successfully.');
        setPcapUploaded(true);
      } else {
        alert('Failed to upload PCAP files. Please check the server.');
      }
    } catch (error) {
      console.error('Error uploading PCAP files:', error);
      alert('An error occurred while uploading the PCAP files.');
    } finally {
      setLoading(false);
    }
  };

  const handleRun = async () => {
    if (!validateFields()) {
      return;
    }

    const fileContent = [
      protocolName,
      fields.length,
      ...fields.map(({ name, size, type, referenceField }) => {
        if (type === 'string/Code/Data') {
          return `${name} 0 char ${referenceField}`;
        }
        if (type === 'fixed-string') {
          return `${name} ${size} char`;
        }
        return `${name} ${size} ${type}`;
      }),
    ].join('\n');

    setLoading(true);

    try {
      const response = await fetch(`${BASE_URL}/data`, {
        method: 'POST',
        headers: {
          'Content-Type': 'text/plain',
        },
        body: fileContent,
      });

      if (response.ok) {
        alert('Protocol run and command executed successfully.');
        setProtocolRuned(true);
      } else {
        alert('Failed to run protocol. Please check the server.');
      }
    } catch (error) {
      console.error('Error running protocol:', error);
      alert('Failed to run protocol. Please check the server.');
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    if (!canSave) {
      alert('Please ensure protocol is run and output is available before saving.');
      return;
    }

    const protocolData = {
      name: protocolName,
      fields: fields,
      files: selectedFiles.map(file => file.name),
      dpi: output,
    };

    try {
      const response = await fetch(`${BASE_URL}/save-protocol`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(protocolData),
      });

      if (response.ok) {
        alert('Protocol configuration saved successfully.');
      } else {
        alert('Failed to save protocol configuration.');
      }
    } catch (error) {
      console.error('Error saving protocol:', error);
      alert('An error occurred while saving the protocol configuration.');
    }
  };

  const downloadDissectorForIP = (ip) => {
    const encodedIP = encodeURIComponent(ip);
    window.open(`${BASE_URL}/download-dissector?ip=${encodedIP}&protocol=${protocolName}`, '_blank');
  };

  const downloadDissectorGlobal = () => {
    window.open(`${BASE_URL}/download-dissector?ip=Global&protocol=${protocolName}`, '_blank');
  };

  const fetchOutput = async () => {
    try {
      const response = await fetch(`${BASE_URL}/output`);
      if (!response.ok) throw new Error('Failed to fetch output');
      const data = await response.json();
      setOutput(data);
    } catch (error) {
      console.error('Error fetching output:', error);
      setOutput({ error: 'Unable to retrieve output. Please try again.' });
    }
  };

  useEffect(() => {
    if (protocolRuned) {
      fetchOutput();
      const intervalId = setInterval(fetchOutput, 5000);
      return () => clearInterval(intervalId);
    }
  }, [protocolRuned]);

  return (
    <div className="max-w-4xl mx-auto p-6 bg-white shadow-2xl rounded-xl">
      <div className="mb-6 bg-gradient-to-r from-blue-500 to-purple-600 p-4 rounded-lg">
        <h1 className="text-3xl font-bold text-white text-center">
          Protocol Configuration
        </h1>
      </div>

      <div className="space-y-6">
        {/* Protocol Name Field */}
        <div className="bg-white border border-gray-200 rounded-lg p-4 shadow-md">
          <h2 className="text-xl font-semibold mb-4 text-gray-800">
            Protocol Name
          </h2>
          <input
            type="text"
            value={protocolName}
            onChange={(e) => setProtocolName(e.target.value)}
            placeholder="Enter protocol name"
            className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            required
          />
        </div>

        {/* Define Protocol Fields Section */}
        <div className="bg-white border border-gray-200 rounded-lg p-4 shadow-md">
          <h2 className="text-xl font-semibold mb-4 text-gray-800">
            Define Protocol Fields
          </h2>
          {fields.map((field, index) => (
            <FieldEditor
              key={index}
              field={field}
              fields={fields}
              index={index}
              onFieldChange={(fieldKey, value) =>
                handleFieldChange(index, fieldKey, value)
              }
              onRemove={() => removeField(index)}
            />
          ))}
          <div className="flex space-x-3 mt-4">
            <button
              onClick={addField}
              className="flex items-center space-x-2 bg-green-500 text-white px-4 py-2 rounded-md hover:bg-green-600 transition-colors"
            >
              <PlusIcon size={20} />
              <span>Add Field</span>
            </button>
          </div>
        </div>

        {/* File Upload Section */}
        <div className="bg-white border border-gray-200 rounded-lg p-4 shadow-md">
          <h2 className="text-xl font-semibold mb-4 text-gray-800">
            File Upload
          </h2>
          <div className="flex flex-col md:flex-row items-center space-y-4 md:space-y-0 md:space-x-4">
            <input
              type="file"
              accept=".pcap,.pcapng"
              onChange={handleFileChange}
              multiple
              className="block w-full text-sm text-gray-500
                         file:mr-4 file:py-2 file:px-4
                         file:rounded-full file:border-0
                         file:text-sm file:font-semibold
                         file:bg-blue-50 file:text-blue-700
                         hover:file:bg-blue-100"
            />
            <button
              onClick={uploadFiles}
              disabled={loading}
              className={`flex items-center space-x-2 px-4 py-2 rounded-md transition-colors ${
                loading
                  ? 'bg-gray-400 cursor-not-allowed'
                  : 'bg-blue-500 text-white hover:bg-blue-600'
              }`}
            >
              <UploadIcon size={20} />
              <span>{loading ? 'Uploading...' : 'Upload'}</span>
            </button>
          </div>
        </div>

        {/* Server Output Section */}
        <div className="bg-white border border-gray-200 rounded-lg p-4 shadow-md">
          <div className="bg-white rounded-lg">
            {output.error ? (
              <div className="text-rose-500 mt-2">{output.error}</div>
            ) : Object.keys(output).length === 0 ? (
              <div className="text-slate-500 mt-2">No output available</div>
            ) : (
              <ProtocolOutputDisplay 
                output={output} 
                onDownload={(ip) => {
                  if (ip === 'global') {
                    downloadDissectorGlobal();
                  } else {
                    downloadDissectorForIP(ip);
                  }
                }} 
              />
            )}
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex justify-center space-x-4 mt-6">
          <button
            onClick={handleRun}
            disabled={loading}
            className={`flex items-center space-x-2 px-6 py-3 rounded-lg text-white font-bold transition-colors ${
              loading
                ? 'bg-gray-400 cursor-not-allowed'
                : 'bg-purple-600 hover:bg-purple-700'
            }`}
          >
            <PlayIcon size={24} />
            <span>{loading ? 'Running...' : 'Run'}</span>
          </button>

          <button
            onClick={handleSave}
            disabled={!canSave}
            className={`flex items-center space-x-2 px-6 py-3 rounded-lg text-white font-bold transition-colors ${
              !canSave
                ? 'bg-gray-400 cursor-not-allowed'
                : 'bg-green-600 hover:bg-green-700'
            }`}
          >
            <SaveIcon size={24} />
            <span>Save</span>
          </button>
        </div>
      </div>
    </div>
  );
};

export default ProtocolEditor;