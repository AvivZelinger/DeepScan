import React from 'react';
import { ChevronDown, ChevronRight, Download, Server } from 'lucide-react';

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
              <Download size={16} />
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

const ProtocolOutputDisplay = ({ output, onDownload }) => {
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-bold text-slate-800">Protocol Analysis Results</h2>
        <button
          onClick={() => onDownload('global')}
          className="flex items-center space-x-2 px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 transition-colors"
        >
          <Download size={18} />
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

export default ProtocolOutputDisplay;