import os
import json
import sys
import adal
import base64
from azure.keyvault import KeyVaultClient, KeyVaultAuthentication
from azure.keyvault import KeyVaultId
from azure.keyvault.custom.key_vault_id import SecretId


#此方法用于加载AAD证书（PEM格式）
def get_private_key(filename):
    with open(filename, 'r') as pem_file:
        private_pem = pem_file.read()
    return private_pem

"""自KeyVault上获取SSL证书的例子."""

#用于读取用来测试的配置数据，此例子中为读取配置文件获取参数信息
# 以下为Azure CDN Service 调用BindCert 传输的参数示例：
#{
#“EndpointId”: “cc9706ec-7f99-4df9-83a9-4820931a2552”,
#“Certificate”:
#“https://transit-cdn-cert.vault.azure.cn/certificates/cc9706ec-7f99-4df9-83a9-4820931a2552”
#“ClientID”: “5451E51E-7E8D481C-BD44-41E25B580F26”
#}
sample_parameters = {}
with open('Config.json', 'r') as f:
    parameters = f.read()
sample_parameters = json.loads(parameters)

#此字段为AAD的ClientId，应取自BindCert Api的ClientID
client_id = sample_parameters['client_id']

#此字段为CDN供应商AAD证书的Thumbprint
client_cert_thumbprint = sample_parameters['aad_cert_thumbprint']

#此字段为CDN供应商AAD证书的文件路径
client_cert = get_private_key(sample_parameters['aad_cert_path'])

#此字段为证书的全路径，应取自BindCert Api的Certificate字段
sslcert_url = sample_parameters['sslcert_url']

def adal_callback(server, resource, scope):
    context = adal.AuthenticationContext(server)
    token = context.acquire_token_with_client_certificate(resource,
    client_id,
    client_cert,
    client_cert_thumbprint)
    return token['tokenType'], token['accessToken']

auth = KeyVaultAuthentication(adal_callback)

client = KeyVaultClient(auth)

#获取SSL证书
secretId = SecretId(sslcert_url)
secret_bundle = client.get_secret(secretId.vault,secretId.name,secretId.version)
print(secret_bundle)

#下载SSL证书并且并保存到本地存储
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



   


    



