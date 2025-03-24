import os
import sys
import struct
import numpy as np
import pandas as pd
import json
import warnings
from collections import defaultdict
from sqlalchemy import create_engine
from scapy.all import rdpcap, UDP, IP
from tensorflow.keras import models
import tensorflow as tf
import joblib
# import catan

##########################################
# MySQL database connection settings
##########################################
DB_USER = 'root'
DB_PASSWORD = 'admin'
DB_HOST = 'localhost'
DB_PORT = '3306'
DB_NAME = 'project'

engine = create_engine(f'mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}')

##########################################
# Read protocol definition table
##########################################
protocol_df = pd.read_sql('select name, size, type, size_field from ProtocolSizesAndType', engine)
if 'is_bitfield' not in protocol_df.columns:
    protocol_df['is_bitfield'] = False

# Build a mapping from field name to its size_field value
protocol_mapping = dict(zip(protocol_df['name'], protocol_df['size_field']))

##########################################
# Parsing routine: parse_pcap_with_ip
##########################################
def parse_pcap_with_ip(pcap_file, protocol_df):
    packets = rdpcap(pcap_file)
    print(f"Total packets: {len(packets)}")
    data = defaultdict(list)
    num = 1
    for pkt in packets:
        print(f"Processing packet {num}...")
        num += 1
        if UDP in pkt and (pkt[UDP].dport == 10000 or pkt[UDP].sport == 10000):
            try:
                src_ip = pkt[IP].src if pkt[UDP].dport == 10000 else pkt[IP].dst
                payload = pkt[UDP].payload.load
                offset = 0
                packet_data = {}
                records = []
                for index, row in protocol_df.iterrows():
                    field_name = row['name']
                    field_size = row['size']
                    field_type = row['type']
                    size_field_name = row['size_field']
                    is_bitfield = bool(row.get('is_bitfield', False))
                    size_defining = None

                    if field_size == 0:
                        remaining_fixed_size = 0
                        for j in range(index + 1, len(protocol_df)):
                            next_field_size = protocol_df.iloc[j]['size']
                            if next_field_size != 0:
                                remaining_fixed_size += next_field_size
                        dynamic_field_size = len(payload) - offset - remaining_fixed_size
                        if pd.notnull(size_field_name) and size_field_name != '':
                            candidate_val = packet_data.get(size_field_name)
                            try:
                                field_size = int(candidate_val) if candidate_val is not None else dynamic_field_size
                            except:
                                field_size = dynamic_field_size
                            size_defining = size_field_name
                        else:
                            field_size = dynamic_field_size
                            size_defining = None

                    if offset + field_size > len(payload):
                        print(f"Not enough data for field '{field_name}' in packet.")
                        break

                    field_bytes = payload[offset:offset + field_size]
                    if is_bitfield or field_type == 'bitfield' or field_type == 'bit':
                        bit_vector = [int(x) for x in format(
                            int.from_bytes(field_bytes, byteorder='big'),
                            '0{}b'.format(field_size * 8)
                        )]
                        bitfields_count = sum(bit_vector)
                        value = bit_vector
                    else:
                        bitfields_count = None
                        if field_type == 'int':
                            value = int.from_bytes(field_bytes, byteorder='big')
                        elif field_type == 'float':
                            value = struct.unpack('!f', field_bytes)[0]
                        elif field_type == 'char':
                            value = field_bytes.decode('utf-8', errors='ignore').strip('\x00')
                        elif field_type == 'bool':
                            value = bool(int.from_bytes(field_bytes, byteorder='big'))
                        elif field_type == 'double':
                            value = struct.unpack('!d', field_bytes)[0]
                        elif field_type == 'long':
                            value = int.from_bytes(field_bytes, byteorder='big')
                        else:
                            value = field_bytes.hex()

                    offset += field_size
                    packet_data[field_name] = value

                    record = {
                        'field_name': field_name,
                        'size': field_size,
                        'value': value,
                        'field_type': field_type,
                        'size_defining_field': size_defining,
                        'bitfields_count': bitfields_count
                    }
                    if is_bitfield or field_type == 'bitfield' or field_type == 'bit':
                        record['bit_vector'] = bit_vector
                    records.append(record)
                if records:
                    data[src_ip].append(records)
            except Exception as e:
                print(f"Error parsing packet: {e}")
                continue
    return data

##########################################
# Feature aggregation functions
##########################################
def extract_aggregated_features(stats):
    sizes = np.array([s['size'] for s in stats])
    numeric_vals = []
    for s in stats:
        try:
            if s['field_type'] in ['int', 'float', 'double', 'long']:
                numeric_vals.append(float(s['value']))
            else:
                numeric_vals.append(0.0)
        except Exception:
            numeric_vals.append(0.0)
    numeric_vals = np.array(numeric_vals)
    features = {
        'count': len(sizes),
        'mean_size': float(sizes.mean()) if len(sizes) > 0 else 0.0,
        'std_size': float(sizes.std()) if len(sizes) > 0 else 0.0,
        'min_size': float(sizes.min()) if len(sizes) > 0 else 0.0,
        'max_size': float(sizes.max()) if len(sizes) > 0 else 0.0,
        'mean_value': float(numeric_vals.mean()) if len(numeric_vals) > 0 else 0.0,
        'std_value': float(numeric_vals.std()) if len(numeric_vals) > 0 else 0.0,
        'min_value': float(numeric_vals.min()) if len(numeric_vals) > 0 else 0.0,
        'max_value': float(numeric_vals.max()) if len(numeric_vals) > 0 else 0.0,
    }
    return features

def create_feature_vector(features):
    return np.array([
        features['count'],
        features['mean_size'],
        features['std_size'],
        features['min_size'],
        features['max_size'],
        features['mean_value'],
        features['std_value'],
        features['min_value'],
        features['max_value']
    ])

##########################################
# DPI Generation using ML models
##########################################
def generate_dpi(endpoints):
    """
    For each endpoint and DPI field, compute aggregated features and then use
    separately trained models to predict:
      - is_dynamic_array, min_size, max_size, min_value, max_value, field_type.
    For the size_defining_field, the protocol definition mapping is used directly.
    Additionally, if the field is a bitfield, compute an aggregated bitfields_count.
    """
    # Define custom objects for loading regression models.
    custom_objects = {'mse': tf.keras.losses.MeanSquaredError()}
    
    # Load the models.
    dpi_model_is_dynamic = models.load_model('/mnt/c/Users/aviv/Desktop/newProject/pythonscripts/ML5/dpi_model_is_dynamic_array.h5', custom_objects=custom_objects) 
    dpi_model_min_size = models.load_model('/mnt/c/Users/aviv/Desktop/newProject/pythonscripts/ML5/dpi_model_min_size.h5', custom_objects=custom_objects)
    dpi_model_max_size = models.load_model('/mnt/c/Users/aviv/Desktop/newProject/pythonscripts/ML5/dpi_model_max_size.h5', custom_objects=custom_objects)
    dpi_model_min_value = models.load_model('/mnt/c/Users/aviv/Desktop/newProject/pythonscripts/ML5/dpi_model_min_value.h5', custom_objects=custom_objects)
    dpi_model_max_value = models.load_model('/mnt/c/Users/aviv/Desktop/newProject/pythonscripts/ML5/dpi_model_max_value.h5', custom_objects=custom_objects)
    dpi_model_field_type = models.load_model('/mnt/c/Users/aviv/Desktop/newProject/pythonscripts/ML5/dpi_model_field_type.h5')
    le_field_type = joblib.load('/mnt/c/Users/aviv/Desktop/newProject/pythonscripts/ML5/dpi_label_encoder_field_type.joblib')

    dpi_result = {}
    for endpoint_ip, packets in endpoints.items():
        field_stats = defaultdict(list)
        for packet in packets:
            for field in packet:
                field_stats[field['field_name']].append(field)
        dpi = {}
        for field_name, stats in field_stats.items():
            features = extract_aggregated_features(stats)
            X_features = create_feature_vector(features).reshape(1, -1)

            # Predict with the models.
            pred_is_dynamic = dpi_model_is_dynamic.predict(X_features)
            pred_min_size = dpi_model_min_size.predict(X_features)
            pred_max_size = dpi_model_max_size.predict(X_features)
            pred_min_value = dpi_model_min_value.predict(X_features)
            pred_max_value = dpi_model_max_value.predict(X_features)
            pred_field_type = dpi_model_field_type.predict(X_features)

            # Get predicted is_dynamic_array from the model.
            is_dynamic_class = np.argmax(pred_is_dynamic, axis=1)[0]
            is_dynamic_array_pred = bool(is_dynamic_class)

            # Override based on protocol definition:
            # If the protocol definition for this field has a non-empty size_field, force True.
            proto_size_field = protocol_mapping.get(field_name, None)
            if proto_size_field is not None and str(proto_size_field).strip() != "":
                is_dynamic_array_pred = True
            else:
                # Otherwise, if the sizes are constant, force False.
                if features['min_size'] == features['max_size']:
                    is_dynamic_array_pred = False

            min_size_pred = float(pred_min_size[0][0])
            max_size_pred = float(pred_max_size[0][0])
            min_value_pred = float(pred_min_value[0][0])
            max_value_pred = float(pred_max_value[0][0])
            
            # Fallback for regression predictions if NaN.
            if np.isnan(min_size_pred):
                min_size_pred = features['min_size']
            if np.isnan(max_size_pred):
                max_size_pred = features['max_size']
            if np.isnan(min_value_pred):
                min_value_pred = features['min_value']
            if np.isnan(max_value_pred):
                max_value_pred = features['max_value']
            
            field_type_class = np.argmax(pred_field_type, axis=1)[0]
            field_type_pred = le_field_type.inverse_transform([field_type_class])[0]

            # Optionally override field_type prediction using aggregated mode.
            aggregated_field_types = pd.Series([s['field_type'] for s in stats if s.get('field_type') is not None])
            aggregated_field_type = aggregated_field_types.mode()[0] if not aggregated_field_types.empty else "unknown"
            if aggregated_field_type != "bitfield":
                field_type_pred = aggregated_field_type

            # Compute aggregated bitfields_count if applicable.
            if isinstance(stats[0]['value'], list):
                bit_counts = [sum(s['value']) for s in stats if isinstance(s['value'], list)]
                aggregated_bit_count = int(round(np.mean(bit_counts))) if bit_counts else None
            else:
                aggregated_bit_count = None

            # For size_defining_field, use the protocol definition mapping.
            size_def_pred = protocol_mapping.get(field_name, None)
            if size_def_pred is None or str(size_def_pred).strip() == "":
                size_def_pred = None

            dpi[field_name] = {
                'is_dynamic_array': is_dynamic_array_pred,
                'min_size': min_size_pred,
                'max_size': max_size_pred,
                'min_value': min_value_pred,
                'max_value': max_value_pred,
                'size_defining_field': size_def_pred,
                'field_type': field_type_pred,
                'bitfields_count': aggregated_bit_count
            }
        dpi_result[endpoint_ip] = dpi
    return dpi_result

##########################################
# Custom JSON encoder for NumPy types
##########################################
class NumpyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        return super(NumpyEncoder, self).default(obj)

##########################################
# Main function
##########################################
def main():
    if len(sys.argv) != 3:
        print(json.dumps({'error': 'Usage: python predict_dpi.py path_to_pcap_file.pcap'}))
        sys.exit(1)
    pcap_file = sys.argv[1]
    if not os.path.exists(pcap_file):
        print(json.dumps({'error': f'PCAP file {pcap_file} does not exist.'}))
        sys.exit(1)
        
    protocol_name = sys.argv[2]

    print(f"Parsing PCAP file: {pcap_file}")
    endpoints = parse_pcap_with_ip(pcap_file, protocol_df)
    if not endpoints:
        print(json.dumps({'error': 'No valid packets found in PCAP file.'}))
        sys.exit(1)
    print("Generating DPI...")
    dpi = generate_dpi(endpoints)
    final_result = {
        'protocol': protocol_name,
        'dpi': dpi}
    output_file = "dpi_output.json"
    with open(output_file, "w", encoding='utf-8') as f:
        json.dump(final_result, f, ensure_ascii=False, indent=4, cls=NumpyEncoder)
    print(f"DPI output saved to {output_file}")

if __name__ == '__main__':
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
    tf.get_logger().setLevel('ERROR')
    warnings.filterwarnings('ignore')
    main()
