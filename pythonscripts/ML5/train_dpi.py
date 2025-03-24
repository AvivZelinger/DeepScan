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
from sklearn.preprocessing import LabelEncoder
from tensorflow.keras import layers, models
import tensorflow as tf
import joblib

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

print(protocol_df)

##########################################
# Parsing function (grouping by IP)
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

                    field_bytes = payload[offset:offset+field_size]
                    if is_bitfield or field_type == 'bitfield':
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
                    if is_bitfield or field_type == 'bitfield':
                        record['bit_vector'] = bit_vector
                    records.append(record)
                if records:
                    data[src_ip].append(records)
            except Exception as e:
                print(f"Error parsing packet: {e}")
                continue
    return data

##########################################
# Aggregation functions for training
##########################################
def extract_aggregated_features(stats):
    sizes = np.array([s['size'] for s in stats])
    numeric_vals = []
    for s in stats:
        try:
            if s['field_type'] in ['int', 'float']:
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
# Model building functions
##########################################
def build_regressor(input_dim):
    model = models.Sequential([
        layers.Input(shape=(input_dim,)),
        layers.Dense(64, activation='relu'),
        layers.Dense(32, activation='relu'),
        layers.Dense(1)
    ])
    model.compile(optimizer='adam', loss='mse')
    return model

def build_classifier(input_dim, num_classes):
    model = models.Sequential([
        layers.Input(shape=(input_dim,)),
        layers.Dense(64, activation='relu'),
        layers.Dense(32, activation='relu'),
        layers.Dense(num_classes, activation='softmax')
    ])
    model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])
    return model

##########################################
# Training function for DPI subfield models
##########################################
def train_dpi_subfield_models(pcap_directory):
    # Gather PCAP files.
    pcap_files = [os.path.join(pcap_directory, f) for f in os.listdir(pcap_directory) if f.endswith('.pcap')]
    if not pcap_files:
        print(f"No PCAP files found in {pcap_directory}.")
        sys.exit(1)
    
    aggregated_endpoints = defaultdict(list)
    for pcap_file in pcap_files:
        print(f"Parsing PCAP file: {pcap_file}")
        endpoints = parse_pcap_with_ip(pcap_file, protocol_df)
        for ip, packets in endpoints.items():
            aggregated_endpoints[ip].extend(packets)
    
    # Aggregate training data per field.
    all_field_stats = defaultdict(list)
    for ip, packets in aggregated_endpoints.items():
        for packet in packets:
            for field in packet:
                all_field_stats[field['field_name']].append(field)
    
    training_data = []
    for field_name, stats in all_field_stats.items():
        features = extract_aggregated_features(stats)
        sizes = [s['size'] for s in stats]
        # Fix: Use protocol definition to force dynamic array if a size_field is defined.
        proto_row = protocol_df[protocol_df['name'] == field_name]
        if not proto_row.empty and pd.notnull(proto_row.iloc[0]['size_field']) and proto_row.iloc[0]['size_field'] != '':
            label_is_dynamic_array = 1
        else:
            label_is_dynamic_array = 1 if len(set(sizes)) > 1 else 0

        label_min_size = min(sizes)
        label_max_size = max(sizes)
        numeric_vals = []
        for s in stats:
            try:
                if s['field_type'] in ['int', 'float']:
                    numeric_vals.append(float(s['value']))
                else:
                    numeric_vals.append(0.0)
            except Exception:
                numeric_vals.append(0.0)
        numeric_vals = numeric_vals if numeric_vals else [0.0]
        label_min_value = min(numeric_vals)
        label_max_value = max(numeric_vals)
        # For field_type, use the aggregated mode from raw data.
        aggregated_field_types = pd.Series([s['field_type'] for s in stats if s.get('field_type') is not None])
        label_field_type = aggregated_field_types.mode()[0] if not aggregated_field_types.empty else "unknown"
        
        training_data.append({
            'field_name': field_name,
            'features': features,
            'is_dynamic_array': label_is_dynamic_array,
            'min_size': label_min_size,
            'max_size': label_max_size,
            'min_value': label_min_value,
            'max_value': label_max_value,
            'field_type': label_field_type
        })
    
    X_list = []
    is_dynamic_y = []
    min_size_y = []
    max_size_y = []
    min_value_y = []
    max_value_y = []
    field_type_y = []
    
    for d in training_data:
        X_list.append(create_feature_vector(d['features']))
        is_dynamic_y.append(d['is_dynamic_array'])
        min_size_y.append(d['min_size'])
        max_size_y.append(d['max_size'])
        min_value_y.append(d['min_value'])
        max_value_y.append(d['max_value'])
        field_type_y.append(d['field_type'])
    
    X = np.vstack(X_list)
    is_dynamic_y = np.array(is_dynamic_y)
    min_size_y = np.array(min_size_y, dtype=np.float32)
    max_size_y = np.array(max_size_y, dtype=np.float32)
    min_value_y = np.array(min_value_y, dtype=np.float32)
    max_value_y = np.array(max_value_y, dtype=np.float32)
    
    # Label encode field_type for classification.
    le_field_type = LabelEncoder()
    field_type_y_enc = le_field_type.fit_transform(field_type_y)
    
    input_dim = X.shape[1]
    epochs = 50
    batch_size = 8

    # Train binary classifier for is_dynamic_array.
    print("Training DPI subfield classifier for is_dynamic_array...")
    model_is_dynamic = build_classifier(input_dim, num_classes=2)
    history_is_dynamic = model_is_dynamic.fit(X, is_dynamic_y, epochs=epochs, batch_size=batch_size, verbose=1)
    print("Is Dynamic Array Model Loss:", history_is_dynamic.history['loss'][-1],
          "Accuracy:", history_is_dynamic.history['accuracy'][-1])
    
    # Train regressors for min_size, max_size, min_value, and max_value.
    print("Training DPI subfield regressor models...")
    model_min_size = build_regressor(input_dim)
    history_min_size = model_min_size.fit(X, min_size_y, epochs=epochs, batch_size=batch_size, verbose=1)
    print("Min Size Model Loss:", history_min_size.history['loss'][-1])
    
    model_max_size = build_regressor(input_dim)
    history_max_size = model_max_size.fit(X, max_size_y, epochs=epochs, batch_size=batch_size, verbose=1)
    print("Max Size Model Loss:", history_max_size.history['loss'][-1])
    
    model_min_value = build_regressor(input_dim)
    history_min_value = model_min_value.fit(X, min_value_y, epochs=epochs, batch_size=batch_size, verbose=1)
    print("Min Value Model Loss:", history_min_value.history['loss'][-1])
    
    model_max_value = build_regressor(input_dim)
    history_max_value = model_max_value.fit(X, max_value_y, epochs=epochs, batch_size=batch_size, verbose=1)
    print("Max Value Model Loss:", history_max_value.history['loss'][-1])
    
    # Train classifier for field_type.
    print("Training DPI subfield classifier model for field_type...")
    model_field_type = build_classifier(input_dim, num_classes=len(le_field_type.classes_))
    history_field_type = model_field_type.fit(X, field_type_y_enc, epochs=epochs, batch_size=batch_size, verbose=1)
    print("Field Type Model Loss:", history_field_type.history['loss'][-1],
          "Accuracy:", history_field_type.history['accuracy'][-1])
    
    # Save all models and encoder.
    model_is_dynamic.save('dpi_model_is_dynamic_array.h5')
    model_min_size.save('dpi_model_min_size.h5')
    model_max_size.save('dpi_model_max_size.h5')
    model_min_value.save('dpi_model_min_value.h5')
    model_max_value.save('dpi_model_max_value.h5')
    model_field_type.save('dpi_model_field_type.h5')
    joblib.dump(le_field_type, 'dpi_label_encoder_field_type.joblib')
    
    print("DPI subfield models trained and saved.")

def main():
    if len(sys.argv) != 2:
        print("Usage: python train_dpi.py path_to_pcap_directory")
        sys.exit(1)
    pcap_directory = sys.argv[1]
    if not os.path.exists(pcap_directory):
        print(f"PCAP directory '{pcap_directory}' does not exist.")
        sys.exit(1)
    train_dpi_subfield_models(pcap_directory)

if __name__ == '__main__':
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
    tf.get_logger().setLevel('ERROR')
    warnings.filterwarnings('ignore')
    main()
