#!/bin/sh
#!/bin/sh

# Create /keys subdir for store the RSA key pair
mkdir -p ./keys

# Create the RSA key pair
openssl genrsa -out ./keys/jwt-key 4096
openssl rsa -in ./keys/jwt-key -pubout > ./keys/jwt-key.pub

# Start the main app
python ./app2.py