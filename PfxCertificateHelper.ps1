# Get client certificate from pfx file
openssl pkcs12 -in [yourfile.pfx] -clcerts -nokeys -out extractedclientcertificate.crt

# Get Certificate Authority certificate from pfx file
openssl pkcs12 -in [yourfile.pfx] -cacerts -nokeys -out extractedcacertificate.crt

# Get Certificate chain (Client certificate + Certificate Authority certificate)
openssl pkcs12 -in [yourfile.pfx] -chain -nokeys -out extractedcertificatechain.crt

# Get encrypted private key from pfx file (a password for the new file will be requested)
openssl pkcs12 -in [yourfile.pfx] -nocerts -out extractedencryptedprivatekey.key

# Get unencrypted private key from key (pem) file
openssl rsa -in extractedencryptedprivatekey.key -out extractedunencryptedprivatekey.key

# Get certificate thumbprint (it needs certificate chain)
openssl x509 -in extractedcertificatechain.crt -fingerprint -noout
