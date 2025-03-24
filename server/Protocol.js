const mongoose = require('mongoose');

const FieldSchema = new mongoose.Schema({
    name: String,
    size: String,
    type: String
});

const DPIFieldSchema = new mongoose.Schema({
    is_dynamic_array: Boolean,
    min_size: Number,
    max_size: Number,
    min_value: mongoose.Schema.Types.Mixed,
    max_value: mongoose.Schema.Types.Mixed,
    size_defining_field: String,
    field_type: String,
    bitfields_count: Number,
});

const DPISchema = new mongoose.Schema({
    ip: String,
    fields: { type: Map, of: DPIFieldSchema } // מפה של שדות לפי IP
});

const ProtocolSchema = new mongoose.Schema({
    name: String,
    fields: [FieldSchema],
    files: [String],
    dpi: [DPISchema] // רשימה של IP ונתוני DPI
});

const Protocol = mongoose.model('Protocol', ProtocolSchema);

module.exports = Protocol;
