#!/bin/bash
server="192.168.1.19"
port=443
url="https://$server:$port"

ciphers_tls12=(
    "TLS_RSA_WITH_AES_128_CBC_SHA"
    "TLS_RSA_WITH_AES_256_CBC_SHA"
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    "TLS_RSA_WITH_RC4_128_SHA"
    "TLS_RSA_WITH_RC4_128_MD5"
    "ECDHE-RSA-AES128-GCM-SHA256"
    "ECDHE-RSA-AES256-GCM-SHA384"
    "ECDHE-ECDSA-AES128-GCM-SHA256"
    "ECDHE-ECDSA-AES256-GCM-SHA384"
    "ECDHE-ECDSA-CHACHA20-POLY1305"
    "ECDHE-RSA-CHACHA20-POLY1305"
    "DHE-RSA-AES128-GCM-SHA256"
    "DHE-RSA-AES256-GCM-SHA384"
    "DHE-RSA-CHACHA20-POLY1305"
)



ciphers_tls13=("TLS_AES_128_GCM_SHA256"
                "TLS_AES_256_GCM_SHA384"
                "TLS_CHACHA20_POLY1305_SHA256"
                "TLS_AES_128_CCM_SHA256"
                "TLS_AES_128_CCM_8_SHA256"
                )

for cipher in "${ciphers_tls12[@]}"; do
                for i in {1..100}; do
                        openssl s_client -connect "$server:$port" -tls1_2 -cipher "$cipher" -alpn "http/1.1,h2"  < /dev/nu>
                sleep 0.1
        done
done
for i in {1..100}; do 
        for cipher in "${ciphers_tls13[@]}";do
        openssl s_client -connect "$server:$port" -tls1_3 -ciphersuites "$cipher" -alpn "http/1.1,h2" < /dev/null &
       sleep 0.1 
        done
done
wait
echo "Traffic generation complete."

