import os
import json
import sys
import adal
import base64
from urllib.parse import urlparse
from azure.keyvault import KeyVaultClient, KeyVaultAuthentication
from azure.keyvault import KeyVaultId

def get_private_key(filename):
    with open(filename, 'r') as pem_file:
        private_pem = pem_file.read()
    return private_pem

def get_keyvaultparts(secretidentifier):
    url = urlparse(secretidentifier)
    keyVaultUrl = url.scheme + "://" + url.netloc
    vauleVersion = url.path.split('/')
    if len(vauleVersion) == 4:
        return keyVaultUrl,vauleVersion[2],vauleVersion[3]
    elif len(vauleVersion) == 3:
        return keyVaultUrl,vauleVersion[2],''

"""Read SSL Cert example."""
sample_parameters = {}

with open('Config.json', 'r') as f:
    parameters = f.read()
sample_parameters = json.loads(parameters)

client_id = sample_parameters['client_id']
client_cert_thumbprint =sample_parameters['aad_cert_thumbprint']
client_cert = get_private_key(sample_parameters['aad_cert_path'])
sslcert_url = sample_parameters['sslcert_url']

keyvault_parts = get_keyvaultparts(sslcert_url)
print(keyvault_parts)

# create a callback to supply the token type and access token on request
def adal_callback(server, resource, scope):
    context = adal.AuthenticationContext(server)
    token = context.acquire_token_with_client_certificate(resource,
    client_id,
    client_cert,
    client_cert_thumbprint)
    return token['tokenType'], token['accessToken']

# create a KeyVaultAuthentication instance which will callback to the
# supplied adal_callback
auth = KeyVaultAuthentication(adal_callback)

# create the KeyVaultClient using the created KeyVaultAuthentication
# instance
client = KeyVaultClient(auth)
secret_bundle = client.get_secret(keyvault_parts[0],keyvault_parts[1],keyvault_parts[2])
print(secret_bundle)

if secret_bundle.content_type == 'application/x-pem-file':
    pemObject = open('output.pem', 'w') 
    pemObject.write(secret_bundle.value)
    pemObject.close()
    print('Save cert to output.pem')

elif secret_bundle.content_type == 'application/x-pkcs12':
    pfxObject = open('output.pfx', 'wb')
    pfxObject.write(base64.b64decode(secret_bundle.value))
    pfxObject.close()
    print('Save cert to output.pfx')



   


    



