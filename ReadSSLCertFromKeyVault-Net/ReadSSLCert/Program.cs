namespace ReadSSLCert
{
    using Microsoft.Azure.KeyVault;
    using Microsoft.IdentityModel.Clients.ActiveDirectory;
    using System;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using System.Configuration;

    class Program
    {
        static void Main(string[] args)
        {
            string CredentialKeyVaultAccessCertThumbprint = ConfigurationManager.AppSettings["CredentialKeyVaultAccessCertThumbprint"]; 
            string CredentialKeyVaultAuthClientId = ConfigurationManager.AppSettings["CredentialKeyVaultAuthClientId"];
            string sslCertUri = ConfigurationManager.AppSettings["sslCertUri"];

            var keyVaultClient = InitWithCert(CredentialKeyVaultAuthClientId, CredentialKeyVaultAccessCertThumbprint);
            Run(keyVaultClient, sslCertUri);

            Console.Read();
        }

        static async void Run(KeyVaultClient keyVaultClient, string sslCertUri)
        {
            var certContentSecret = await keyVaultClient.GetSecretAsync(sslCertUri).ConfigureAwait(false);

            Console.WriteLine(certContentSecret.ContentType);
            Console.WriteLine(certContentSecret.Value);
        }

        static private KeyVaultClient InitWithCert(string authClientId, string authThumbprint)
        {
            X509Certificate2 cert = GetCertificateByThumbprint(authThumbprint, StoreName.My, StoreLocation.LocalMachine);

            ClientAssertionCertificate assertionCert = new ClientAssertionCertificate(authClientId, cert);

            KeyVaultClient client = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(
                                       (authority, resource, scope)
                                           => GetAccessTokenWithCert(authority, resource, scope, assertionCert)));
            return client;
        }

        static async Task<string> GetAccessTokenWithCert(string authority, string resource, string scope, ClientAssertionCertificate assertionCert)
        {
            AuthenticationContext context = new AuthenticationContext(authority, TokenCache.DefaultShared);
            AuthenticationResult result = await context.AcquireTokenAsync(resource, assertionCert).ConfigureAwait(false);
            return result.AccessToken;
        }

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
