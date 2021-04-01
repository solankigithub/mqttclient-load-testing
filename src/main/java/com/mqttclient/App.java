package com.mqttclient;


import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileReader;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.eclipse.paho.client.mqttv3.IMqttDeliveryToken;
import org.eclipse.paho.client.mqttv3.MqttCallback;
import org.eclipse.paho.client.mqttv3.MqttCallbackExtended;
import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttMessage;



/**
 * Hello world!
 *
 */
public class App extends Thread implements MqttCallback
{
	
	public static String caFilePath = "src/main/resources/certs/ca.crt";
	public static String clientCrtFilePath = "src/main/resources/certs/client.crt";
	public static String clientKeyFilePath = "src/main/resources/certs/client.key";
	public static String serverURL = "ssl://ec2-35-174-111-140.compute-1.amazonaws.com:8883";
	
	public MqttClient client;
	
	private String macID;
	
    public static void main( String[] args )
    {
    	int no_of_devices = 2000;
    	
    	List<String> macids = new ArrayList<String>();
    	
    	for(int i=0; i<no_of_devices;i++) {
    		macids.add("ZZ:ZZ:ZZ:ZZ:ZZ:" + String.valueOf(i));    		
    	}
										    	
    	for(int i=0; i<macids.size();i++) {
    		try {
    			//Thread.sleep(100);
    		}
    		catch(Exception ex) {
    			System.out.println("Exception is Thread Sleep");
    		}
    		App client = new App(macids.get(i));
    		client.start();
    	}
    	
    }
    
    
    public App(String macID) {
		// TODO Auto-generated constructor stub
    	this.macID = macID;
	}
    
    
    @Override
	public void run() {
		// TODO Auto-generated method stub
		super.run();
		startAgent();
	}


	public void startAgent() {
		String clientId = "Client" + Math.random();
		System.out.println("Client Id : " + clientId);
		try{
			client = new MqttClient(serverURL, clientId);
			MqttConnectOptions options = new MqttConnectOptions();
			options.setConnectionTimeout(0);
			options.setKeepAliveInterval(60);
			options.setMqttVersion(MqttConnectOptions.MQTT_VERSION_3_1);
			
			SSLSocketFactory socketFactory = getSocketFactory(caFilePath,
					clientCrtFilePath, clientKeyFilePath, "");
			
			
			options.setSocketFactory(socketFactory);
			System.out.println("starting connect the server...");
			client.connect(options);
			System.out.println("connected!");
			
			System.out.println("Execution started for " + macID);
			int i=0;
			while(i<20000) 
			{
				MqttMessage message = new MqttMessage();
				message.setQos(1);
				long currentTime = System.currentTimeMillis();
				String payload = "{\"time\":" + currentTime + ",\"press\":100,\"temp\":100,\"oil\":100,\"rpm\":100,\"humidity\":100,\"current\":100}";
				message.setPayload(payload.getBytes());
				client.publish(this.macID + "/data", message);
				i++;
			}
			
			System.out.println("Execution finished for " + macID);
			
		}
		catch(Exception ex) {
			ex.printStackTrace();
		}
	}
	
	
	
	
	private static SSLSocketFactory getSocketFactory(final String caCrtFile,
			final String crtFile, final String keyFile, final String password)
			throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		// load CA certificate
		X509Certificate caCert = null;
		
		FileInputStream fis = new FileInputStream(caCrtFile);
		BufferedInputStream bis = new BufferedInputStream(fis);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");

		while (bis.available() > 0) {
			caCert = (X509Certificate) cf.generateCertificate(bis);
			// System.out.println(caCert.toString());
		}

		// load client certificate
		bis = new BufferedInputStream(new FileInputStream(crtFile));
		X509Certificate cert = null;
		while (bis.available() > 0) {
			cert = (X509Certificate) cf.generateCertificate(bis);
			// System.out.println(caCert.toString());
		}

		// load client private key
		PEMParser pemParser = new PEMParser(new FileReader(keyFile));
		Object object = pemParser.readObject();
		PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder()
				.build(password.toCharArray());
		JcaPEMKeyConverter converter = new JcaPEMKeyConverter()
				.setProvider("BC");
		KeyPair key;
		if (object instanceof PEMEncryptedKeyPair) {
			System.out.println("Encrypted key - we will use provided password");
			key = converter.getKeyPair(((PEMEncryptedKeyPair) object)
					.decryptKeyPair(decProv));
		} else {
			System.out.println("Unencrypted key - no password needed");
			key = converter.getKeyPair((PEMKeyPair) object);
		}
		pemParser.close();

		// CA certificate is used to authenticate server
		KeyStore caKs = KeyStore.getInstance(KeyStore.getDefaultType());
		caKs.load(null, null);
		caKs.setCertificateEntry("ca-certificate", caCert);
		TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509");
		tmf.init(caKs);

		// client key and certificates are sent to server so it can authenticate
		// us
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(null, null);
		ks.setCertificateEntry("certificate", cert);
		ks.setKeyEntry("private-key", key.getPrivate(), password.toCharArray(),
				new java.security.cert.Certificate[] { cert });
		KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory
				.getDefaultAlgorithm());
		kmf.init(ks, password.toCharArray());

		// finally, create SSL socket factory
		SSLContext context = SSLContext.getInstance("TLSv1.2");
		context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

		return context.getSocketFactory();
	}
	
	
    public void connectionLost(Throwable cause) {
    	// TODO Auto-generated method stub
    	System.out.println("MQTT Connection lost...\nTrying to connect again...");
    	try {
    		this.startAgent();
    	}
    	catch(Exception ex) {
    		System.out.println("MQTT Connection failed...");
    	}
    	
    }
    
    public void deliveryComplete(IMqttDeliveryToken token) {
    	// TODO Auto-generated method stub
    	
    }
    
    public void messageArrived(String topic, MqttMessage message) throws Exception {
    	// TODO Auto-generated method stub
    	
    }
    
    
}
