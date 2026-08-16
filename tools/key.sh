rm -rf ../tmp

mkdir -p ../tmp/key

openssl genpkey -algorithm RSA -out ../tmp/key/private_key.pem -pkeyopt rsa_keygen_bits:4096

openssl rsa -pubout -in ../tmp/key/private_key.pem -out ../tmp/key/public_key.pem