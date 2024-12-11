import pyshark
from OpenSSL import crypto
import pandas as pd
import numpy as np  # For handling NaN values

# Replace with your .pcap file
pcap_file = 'complaint_demo.pcap'

# Define forward secrecy ciphers
forward_secrecy_ciphers = [
    "0xc02b",  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (TLS 1.2)
    "0xc02c",  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (TLS 1.2)
    "0xc02f",  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (TLS 1.2)
    "0xc030",  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (TLS 1.2)
    "0xcc13",  # TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (TLS 1.2)
    "0xcc14",  # TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (TLS 1.2)
    "0x009e",  # TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (TLS 1.2)
    "0x009f",  # TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (TLS 1.2)
    # TLS 1.3 Cipher Suites
    "0x1301",  # TLS_AES_128_GCM_SHA256
    "0x1302",  # TLS_AES_256_GCM_SHA384
    "0x1303",  # TLS_CHACHA20_POLY1305_SHA256
    "0x1304",  # TLS_AES_128_CCM_SHA256
    "0x1305",  # TLS_AES_128_CCM_8_SHA256
]

# TLS 1.3 cipher suites
tls_13_ciphers = [
    "0x1301",  # TLS_AES_128_GCM_SHA256
    "0x1302",  # TLS_AES_256_GCM_SHA384
    "0x1303",  # TLS_CHACHA20_POLY1305_SHA256
    "0x1304",  # TLS_AES_128_CCM_SHA256
    "0x1305",  # TLS_AES_128_CCM_8_SHA256
]

# Data to store stream-level details
stream_data = {}

# Function to process the certificate and extract details
def process_certificate(raw_cert_data):
    try:
        # Remove colons and convert to bytes
        cert_data = bytes.fromhex(raw_cert_data.replace(':', ''))
        # Load the certificate
        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_data)
        # Extract public key length
        key_length = cert.get_pubkey().bits()
        # Extract signature algorithm
        signature_algorithm = cert.get_signature_algorithm().decode()
        return key_length, signature_algorithm
    except Exception as e:
        print(f"Failed to process certificate: {e}")
        return None, None

# Extract fields for a packet and update stream data
def update_stream_data(packet, stream_id):
    try:
        if stream_id not in stream_data:
            stream_data[stream_id] = {
                'protocol_version': np.nan,
                'cipher_suite': np.nan,
                'forward_secrecy': 'No',
                'certificate_key_length': 0,
                'signature_algorithm': 'No',
            }

        # Extract protocol version and cipher suite
        if hasattr(packet.tls, 'handshake_version'):
            stream_data[stream_id]['protocol_version'] = packet.tls.handshake_version
        if hasattr(packet.tls, 'handshake_ciphersuite'):
            cipher_suite = packet.tls.handshake_ciphersuite
            stream_data[stream_id]['cipher_suite'] = cipher_suite
            if cipher_suite in forward_secrecy_ciphers:
                stream_data[stream_id]['forward_secrecy'] = 'Yes'

            # Force protocol version to 0x0304 for TLS 1.3 cipher suites
            if cipher_suite in tls_13_ciphers:
                stream_data[stream_id]['protocol_version'] = '0x0304'

        # Extract certificate key length and signature algorithm
        if hasattr(packet.tls, 'handshake_certificate'):
            raw_cert_data = getattr(packet.tls, 'handshake_certificate', None)
            if raw_cert_data:
                key_length, signature_algorithm = process_certificate(raw_cert_data)
                stream_data[stream_id]['certificate_key_length'] = key_length
                stream_data[stream_id]['signature_algorithm'] = signature_algorithm

    except AttributeError as e:
        print(f"AttributeError: {e}")

# Process packets
capture = pyshark.FileCapture(pcap_file, display_filter='tls')
for packet in capture:
    try:
        stream_id = getattr(packet.tcp, 'stream', None)
        if stream_id is not None:
            update_stream_data(packet, stream_id)
    except AttributeError as e:
        print(f"AttributeError while processing packet: {e}")
        continue

capture.close()

# Convert to DataFrame and handle missing values
df_streams = pd.DataFrame.from_dict(stream_data, orient='index').reset_index()
df_streams.rename(columns={'index': 'stream_id'}, inplace=True)

# Ensure all missing values are represented as NaN
df_streams.fillna(value=np.nan, inplace=True)

# Save to CSV
output_file = 'test.csv'
df_streams.to_csv(output_file, index=False)

print(f"Extracted data saved to {output_file}.")
