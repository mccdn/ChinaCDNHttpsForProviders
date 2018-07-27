package com.microsoft;

import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.models.*;
import java.util.Properties;

public class RetrieveSSLCertSample
{
    public static void main( String[] args )
    {
        try{
            Properties props = new Properties();
            props.load(Thread.currentThread().getContextClassLoader().getResourceAsStream("azure.properties"));

            final String clientId = props.getProperty("CredentialKeyVaultAuthClientId");
            final String pfxPassword = props.getProperty("pfxPassword");
            final String path = props.getProperty("pathPfx");
            final String certUri = props.getProperty("sslCertUri");

            JavaKeyVaultAuthenticator authenticator = new JavaKeyVaultAuthenticator();
            KeyVaultClient kvClient = authenticator.getAuthentication(path, pfxPassword, clientId);            
            SecretBundle secretBundle= kvClient.getSecret(certUri);
            String secretValue = secretBundle.value();
            System.out.println("Secret in Key Vault Value: " + secretValue);            
        }
        catch(Exception e){
            e.printStackTrace();
        }
    }
}

