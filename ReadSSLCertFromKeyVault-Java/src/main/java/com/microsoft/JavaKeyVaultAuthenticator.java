package com.microsoft;

import com.microsoft.aad.adal4j.AsymmetricKeyCredential;
import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.concurrent.Executors;

public class JavaKeyVaultAuthenticator {
	public KeyVaultClient getAuthentication(String path, String pfxPassword, String clientId)
			throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException,
			NoSuchProviderException, IOException {

		KeyCert certificateKey = readPfx(path, pfxPassword);

		PrivateKey privateKey = certificateKey.getKey();

		// 基于证书的认证
		KeyVaultClient keyVaultClient = new KeyVaultClient(new KeyVaultCredentials() {

			@Override
			public String doAuthenticate(String authorization, String resource, String scope) {

				AuthenticationContext context;
				try {
					context = new AuthenticationContext(authorization, false, Executors.newFixedThreadPool(1));
					AsymmetricKeyCredential asymmetricKeyCredential = AsymmetricKeyCredential.create(clientId,
							privateKey, certificateKey.getCertificate());
					AuthenticationResult result = context.acquireToken(resource, asymmetricKeyCredential, null).get();

					return result.getAccessToken();
				} catch (Exception e) {
					e.printStackTrace();
				}
				return "";
			}
		});
		return keyVaultClient;
	}
	
	//读取PFX证书
	public static KeyCert readPfx(String path, String password) throws NoSuchProviderException, KeyStoreException,
			IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {

		try (FileInputStream stream = new FileInputStream(path)) {
			KeyCert keyCert = new KeyCert(null, null);

			boolean isAliasWithPrivateKey = false;

			// 访问Java KeyStore
			final KeyStore store = KeyStore.getInstance("pkcs12", "SunJSSE");

			// 加载Java KeyStore
			store.load((InputStream) stream, password.toCharArray());

			// 枚举所有Aliases来查找Private Key
			Enumeration<String> aliases = store.aliases();
			String alias = "";
			while (aliases.hasMoreElements()) {
				alias = aliases.nextElement();
				System.out.println(alias);

				if (isAliasWithPrivateKey = store.isKeyEntry(alias)) {
					break;
				}
			}

			if (isAliasWithPrivateKey) {
				
				//从Java KeyStore中获取证书
				X509Certificate certificate = (X509Certificate) store.getCertificate(alias);
				System.out.println("the alias is: " + alias);

				//从Java KeyStore中获取私钥
				PrivateKey key = (PrivateKey) store.getKey(alias, password.toCharArray());

				keyCert.setCertificate(certificate);
				keyCert.setKey(key);

				System.out.println("key in primary encoding format is: " + key.getEncoded());
			}
			return keyCert;
		}
	}

}

class KeyCert {

	X509Certificate certificate;
	PrivateKey key;

	public KeyCert(X509Certificate certificate, PrivateKey key) {
		this.certificate = certificate;
		this.key = key;
	}

	public X509Certificate getCertificate() {
		return certificate;
	}

	public void setCertificate(X509Certificate certificate) {
		this.certificate = certificate;
	}

	public PrivateKey getKey() {
		return key;
	}

	public void setKey(PrivateKey key) {
		this.key = key;
	}
}
