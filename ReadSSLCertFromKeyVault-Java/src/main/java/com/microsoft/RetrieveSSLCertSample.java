package com.microsoft;

import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.models.*;
import java.util.Properties;

import org.apache.commons.codec.binary.Base64;

import java.io.*;

public class RetrieveSSLCertSample {
	public static void main(String[] args) {
		try {
			Properties props = new Properties();
			props.load(Thread.currentThread().getContextClassLoader().getResourceAsStream("azure.properties"));

			final String clientId = props.getProperty("CredentialKeyVaultAuthClientId");
			final String pfxPassword = props.getProperty("pfxPassword");
			final String path = props.getProperty("pathPfx");
			final String certUri = props.getProperty("sslCertUri");

			JavaKeyVaultAuthenticator authenticator = new JavaKeyVaultAuthenticator();
			KeyVaultClient kvClient = authenticator.getAuthentication(path, pfxPassword, clientId);
			SecretBundle secretBundle = kvClient.getSecret(certUri);
			String secretValue = secretBundle.value();
			System.out.println("Secret in Key Vault Value: " + secretValue);

			String contentType = secretBundle.contentType();
			System.out.println("Secret in Key Vault content type: " + contentType);
			if (contentType.equals("application/x-pem-file")) {
				// PEM.
				File myFilePath = new File("test.pem");
				if (!myFilePath.exists()) {
					myFilePath.createNewFile();
				}
				FileWriter fw = new FileWriter(myFilePath);
				fw.write(secretValue);
				fw.flush();
				fw.close();

			} else if (contentType.equals("application/x-pkcs12")) {
				// PFX.
				File myFilePath = new File("test.pfx");
				if (!myFilePath.exists()) {
					myFilePath.createNewFile();
				}

				FileOutputStream output = new FileOutputStream(myFilePath);
				output.write(Base64.decodeBase64(secretValue));
				output.flush();
				output.close();				
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
