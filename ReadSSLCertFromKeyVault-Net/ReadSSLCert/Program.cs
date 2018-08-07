namespace ReadSSLCert
{
    using Microsoft.Azure.KeyVault;
    using Microsoft.IdentityModel.Clients.ActiveDirectory;
    using System;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using System.Configuration;
    using Microsoft.Azure.KeyVault.Models;
    using System.IO;
    using System.Text;

    class Program
    {
        static void Main(string[] args)
        {
            //此字段为AAD证书的Thumbprint，用来查找本地安装证书并初始化密钥保管库。
            string credentialKeyVaultAccessCertThumbprint = ConfigurationManager.AppSettings["CredentialKeyVaultAccessCertThumbprint"];

            //此字段为AAD的ClientId，取自BindCert Api的ClientID
            string credentialKeyVaultAuthClientId;

            //此字段为证书的全路径，取自BindCert Api的Certificate字段
            string sslCertUri;

            //此字段为供应商端的Provider Id，，取自BindCert Api的EndpointId字段
            string endpointId;

            //从BindCert HttpRequest中获取参数。
            ReadParametersFromBindCertHttpRequest(out credentialKeyVaultAuthClientId, out sslCertUri, out endpointId);

            //通过本地AAD证书初始化密钥保管库的客户端
            var keyVaultClient = InitKeyVaultWithAADCert(credentialKeyVaultAuthClientId, credentialKeyVaultAccessCertThumbprint);

            //通过密钥保管库客户端获取证书并保存到本地。
            GetAndDownLoadSSLCert(keyVaultClient, sslCertUri);

            Console.Read();
        }

        /// <summary>
        /// 从BindCert Api的http request中获取参数
        /// </summary>
        /// <param name="authClientId">此字段为AAD的ClientId，实际应取自BindCert Api的ClientID</param>
        /// <param name="sslCertUri">此字段为证书的全路径，适应应取自BindCert Api的Certificate字段</param>
        /// <param name="endpointId">供应商端的Endpoint Id.适应应取自BindCert Api的EndpointId字段</param>
        static void ReadParametersFromBindCertHttpRequest(out string authClientId, out string sslCertUri, out string endpointId)
        {
            ///// 以下为Azure CDN Service 调用BindCert 传输的参数示例：
            ////{ 
            ////“EndpointId”: “cc9706ec-7f99-4df9-83a9-4820931a2552”, 
            ////“Certificate”: “https://transit-cdn-cert.vault.azure.cn/certificates/cc9706ec-7f99-4df9-83a9-4820931a2552” 
            ////“ClientID”: “5451E51E-7E8D481C-BD44-41E25B580F26” 
            ////}

            //此字段为AAD的ClientId，实际应取自BindCert Api的ClientID
            authClientId = ConfigurationManager.AppSettings["CredentialKeyVaultAuthClientId"];

            //此字段为证书的全路径，实际应取自BindCert Api的Certificate字段
            sslCertUri = ConfigurationManager.AppSettings["sslCertUri"];

            //供应商端的Endpoint Id.实际应取自BindCert Api的EndpointId字段
            endpointId = Guid.NewGuid().ToString();
        }


        /// <summary>
        /// 获取并下载SSL证书
        /// </summary>
        /// <param name="keyVaultClient">用来访问密钥保管库的客户端</param>
        /// <param name="sslCertUri">SSL Cert的Uri路径，此路径从BindCert的参数Certificate中获取到</param>
        static async void GetAndDownLoadSSLCert(KeyVaultClient keyVaultClient, string sslCertUri)
        {
            var certContentSecret = await keyVaultClient.GetSecretAsync(sslCertUri).ConfigureAwait(false);

            Console.WriteLine(certContentSecret.ContentType);
            Console.WriteLine(certContentSecret.Value);

            if (string.CompareOrdinal(certContentSecret.ContentType, CertificateContentType.Pem) == 0)
            {
                //Pem文件.
                using (FileStream fs = new FileStream($"{Guid.NewGuid()}.pem", FileMode.Create))
                {
                    byte[] content = Encoding.UTF8.GetBytes(certContentSecret.Value);
                    fs.Write(content, 0, content.Length);
                    fs.Flush();
                }
            }
            else if (string.CompareOrdinal(certContentSecret.ContentType, CertificateContentType.Pfx) == 0)
            {
                //PFX 文件
                using (FileStream fs = new FileStream($"{Guid.NewGuid()}.pfx", FileMode.Create))
                {
                    byte[] content = Convert.FromBase64String(certContentSecret.Value);
                    fs.Write(content, 0, content.Length);
                    fs.Flush();
                }
            }
            else
            {
                throw new FormatException("Invalid certificate format");
            }
        }

        /// <summary>
        /// 通过本地AAD证书初始化密钥保管库的客户端
        /// </summary>
        /// <param name="authClientId">此字段为AAD的ClientId，实际应取自BindCert Api的ClientID</param>
        /// <param name="authThumbprint">此字段为AAD证书的Thumbprint，用来查找本地安装证书并初始化密钥保管库。</param>
        /// <returns>获取密钥保管库的客户端。</returns>
        static private KeyVaultClient InitKeyVaultWithAADCert(string authClientId, string authThumbprint)
        {
            X509Certificate2 cert = GetCertificateByThumbprint(authThumbprint, StoreName.My, StoreLocation.LocalMachine);

            ClientAssertionCertificate assertionCert = new ClientAssertionCertificate(authClientId, cert);

            KeyVaultClient client = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(
                                       async (authority, resource, scope) =>
                                       {
                                           AuthenticationContext context = new AuthenticationContext(authority, TokenCache.DefaultShared);
                                           AuthenticationResult result = await context.AcquireTokenAsync(resource, assertionCert).ConfigureAwait(false);
                                           return result.AccessToken;
                                       }));
            return client;
        }

        /// <summary>
        /// 获取本地已安装证书
        /// </summary>
        /// <param name="thumbprint">证书的thumbprint.</param>
        /// <param name="name">证书存储的名称</param>
        /// <param name="location">证书存储的地址（Localmachine/CurrentUser）</param>
        /// <returns>返回X509证书</returns>
        static X509Certificate2 GetCertificateByThumbprint(string thumbprint, StoreName name, StoreLocation location)
        {
            var certStore = new X509Store(name, location);
            try
            {
                certStore.Open(OpenFlags.ReadOnly);
                var certCllection = certStore.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);

                if (certCllection.Count > 0)
                {
                    return certCllection[0];
                }
                else
                {
                    return null;
                }
            }
            finally
            {
                certStore.Close();
            }
        }
    }
}
