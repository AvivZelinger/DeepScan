import React from 'react';
import { TrashIcon } from 'lucide-react';

// Define the available field types and their corresponding sizes
const FIELD_TYPES = [
  { type: 'int', size: 4 },
  { type: 'float', size: 4 },
  { type: 'char', size: 1 },
  { type: 'string/Code/Data', size: 0 }, // Special case for undefined
  { type: 'double', size: 8 },
  { type: 'bool', size: 1 },
  { type: 'custom', size: null }, // Allow custom size
{type: 'bitfield', size: null}
];

const FieldEditor = ({ field, onFieldChange, onRemove }) => {
  const handleTypeChange = (value) => {
    const selectedType = FIELD_TYPES.find((option) => option.type === value);
    onFieldChange('type', value);
    if (selectedType && selectedType.size !== null) {
      onFieldChange('size', selectedType.size.toString());
    } else {
      onFieldChange('size', ''); // Clear size for custom or undefined types
    }
  };

  return (
    <div className="flex flex-col md:flex-row items-start md:items-center space-y-4 md:space-y-0 md:space-x-4 mb-3 p-3 bg-gray-100 rounded-lg shadow-sm">
      {/* Field Name */}
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

      {/* Field Type */}
        <div className="w-full md:w-1/4">
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Field Type
          </label>
          <select
            value={field.type}
            onChange={(e) => handleTypeChange(e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            {FIELD_TYPES.map((option) => (
          <option key={option.type} value={option.type}>
            {option.type.charAt(0).toUpperCase() + option.type.slice(1)}
          </option>
            ))}
          </select>
        </div>

        {/* Field Size */}
        <div className="w-full md:w-1/4">
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Field Size
          </label>
          <input
            value={field.type === 'string/Code/Data' ? 'undefined' : field.size}
            onChange={(e) => onFieldChange('size', e.target.value)}
            className={`w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 ${
          field.type === 'custom' || field.size === ''
            ? 'focus:ring-blue-500'
            : 'bg-gray-200 cursor-not-allowed'
            }`}
            placeholder="Enter byte size"
            disabled={field.type !== 'custom' && field.size !== ''}
          />
        </div>

        {/* Remove Field Button */}
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

export default FieldEditor;
