package com.microsoft;

import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.models.*;
import java.util.Properties;

import org.apache.commons.codec.binary.Base64;

import java.io.*;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class RetrieveSSLCertSample {
	public static void main(String[] args) {
		try {
			
			//从BindCert Api的http request中获取参数
			///// 以下为Azure CDN Service 调用BindCert 传输的参数示例：
            ////{ 
            ////“EndpointId”: “cc9706ec-7f99-4df9-83a9-4820931a2552”, 
            ////“Certificate”: “https://transit-cdn-cert.vault.azure.cn/certificates/cc9706ec-7f99-4df9-83a9-4820931a2552” 
            ////“ClientID”: “5451E51E-7E8D481C-BD44-41E25B580F26” 
            ////}
			
			Properties props = new Properties();
			props.load(Thread.currentThread().getContextClassLoader().getResourceAsStream("azure.properties"));

		    //此字段为AAD的ClientId，应取自BindCert Api的ClientID
			final String clientId = props.getProperty("CredentialKeyVaultAuthClientId");
			
			//AAD证书的Password
			final String pfxPassword = props.getProperty("pfxPassword");
			
			//AAD证书的本地路径
			final String path = props.getProperty("pathPfx");
			
            //此字段为SSL证书的全路径，应取自BindCert Api的Certificate字段
			final String certUri = props.getProperty("sslCertUri");
			
            //通过本地AAD证书初始化密钥保管库的客户端
			KeyVaultClient keyVaultClient = InitKeyVaultWithAADCert(path,pfxPassword,clientId);			
			
			//通过密钥保管库客户端获取证书并保存到本地。
            GetAndDownLoadSSLCert(keyVaultClient, certUri);		
		
		} catch (Exception e) {
			e.printStackTrace();
		}
	}	

    // 获取并下载SSL证书
    private static void GetAndDownLoadSSLCert(KeyVaultClient keyVaultClient, String certUri) {    	
    	try {
			SecretBundle secretBundle = keyVaultClient.getSecret(certUri);
			String secretValue = secretBundle.value();
			System.out.println("Secret in Key Vault Value: " + secretValue);

			String contentType = secretBundle.contentType();
			System.out.println("Secret in Key Vault content type: " + contentType);
			if (contentType.equals("application/x-pem-file")) {
				// PEM证书.
				File myFilePath = new File("test.pem");
				if (!myFilePath.exists()) {
					myFilePath.createNewFile();
				}
				FileWriter fw = new FileWriter(myFilePath);
				fw.write(secretValue);
				fw.flush();
				fw.close();

			} else if (contentType.equals("application/x-pkcs12")) {
				// PFX证书.
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

	// 通过本地AAD证书初始化密钥保管库的客户端
	private static KeyVaultClient InitKeyVaultWithAADCert(String pfxPath,String pfxPassword,String clientId)
	{
		JavaKeyVaultAuthenticator authenticator = new JavaKeyVaultAuthenticator();
		KeyVaultClient kvClient;
		try {
			kvClient = authenticator.getAuthentication(pfxPath, pfxPassword, clientId);
			return kvClient;
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return null;
	}
}
