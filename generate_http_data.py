import warnings
import h2.connection
import h2.events
import scapy.all as scapy
import requests
import logging
import random
import csv
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urlparse
from URLS import public_urls

num_requests=25
def generate_compliant_request(url):
    try:
        http_version = random.choice(["HTTP/1.1", "HTTP/2"])
        session = requests.Session()
        session.mount(url, requests.adapters.HTTPAdapter())  # Ensures HTTP/2 is supported

        response = session.get(
            url,
            verify=False,
            timeout=10,
            headers={"Upgrade": "h2c"} if http_version == "HTTP/2" else None,
        )

        hsts = response.headers.get('Strict-Transport-Security')
        csp = response.headers.get('Content-Security-Policy')
        compression = response.headers.get('content-encoding')
        xframe = response.headers.get('x-frame-options')

        status_code = response.status_code


        return {
            "HTTP Version": http_version,
            "HSTS": hsts,
            "CSP": csp,
            "Compression": compression,
            "Status Code": status_code,
            "XFrame-Options": xframe,
        }
    except requests.RequestException as e:
        logging.error(f"Request error to {url}: {e}")
        return None


def preprocess_fields(hsts, csp, compression, xframe):
    if hsts == 'True' and (csp != 'unsafe-inline' and csp != 'unsafe-eval') and compression in ['gzip', 'brotli'] and xframe in ['DENY', 'SAMEORIGIN']:
        return True
    return False



def create_http2_frame(url):

    parsed_url = urlparse(url)
    host = parsed_url.netloc
    path = parsed_url.path or "/"
    port = 443
    connection = h2.connection.H2Connection()

    connection.initiate_connection()
    headers = [
        (':method', 'GET'),
        (':path', path),
        (':scheme', 'https'),
        (':authority', host),
    ]
    connection.send_headers(1, headers)
    connection.send_data(1, b"", end_stream=True)
    frames = connection.data_to_send()
    ip_packet = scapy.IP(dst=host)
    tcp_packet = scapy.TCP(dport=port, sport=random.randint(1024, 65535), flags="PA", seq=1000)
    packet = ip_packet / tcp_packet / scapy.Raw(load=bytes(frames))
    return packet


def generate_requests_and_pcap(num_requests=num_requests, csv_filename="http_raw.csv", pcap_filename="http2_traffic.pcap"):



    fieldnames = ["HTTP Version", "HSTS", "CSP", "Compression", "XFrame-Options"]
    warnings.simplefilter('ignore', InsecureRequestWarning)
    all_requests = []

    with open(csv_filename, mode="w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()

        for _ in range(num_requests):
            url = random.choice(public_urls)
            request_data = generate_compliant_request(url)
            if request_data:

                writer.writerow({key: request_data[key] for key in fieldnames})

                all_requests.append(request_data)

    print(f"{num_requests} requests saved to {csv_filename}")



generate_requests_and_pcap()
