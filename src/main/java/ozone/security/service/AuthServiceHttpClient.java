package ozone.security.service;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIUtils;
import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.NoSuchAlgorithmException;

public class AuthServiceHttpClient {
    protected KeyStore trustStore;
    protected char[] trustStorePass;

    protected KeyStore clientKS;
    protected String trustStorePath;
    protected String clientKSPath;
    protected char[] clientKSPass;

    // private String baseURL;
    private String baseURL; 
    private URL requestURL;
    private String projectName;
    private int maxConnectionsPerRoute = 5;

    private CloseableHttpClient client;


    private static final Log logger = LogFactory.getLog(AuthServiceHttpClient.class);

    private KeyStore loadJKSFromFile(String ksPath, char[]  ksPass) {
	KeyStore newJKS = null;
	FileInputStream jksStream = null;

	try {
	    newJKS = KeyStore.getInstance("JKS");
	} catch (KeyStoreException kse) {
	    logger.error("Error getting default instance of JKS keystore: " + kse);
	}

	if (newJKS != null) {
	    try {
		jksStream = new FileInputStream(new File(ksPath));
		newJKS.load(jksStream, ksPass);
	    } catch (NoSuchAlgorithmException nsae) {
		logger.error("Could not load algorithm used to verify KeyStore integrity: " + nsae);
	    } catch (IOException ioe) {
		if (ioe.getCause() instanceof UnrecoverableKeyException) {
		    logger.error("Invalid Password for KeyStore: " + ioe);
		} else {
		    logger.error("I/O Error occurred opening KeyStore: " + ioe);
		}
	    } catch (CertificateException ce) {
		logger.error("Unable to load a certificate from the KeyStore: " + ce);
	    }
	}
	
	return newJKS;
    }

    @PostConstruct
    public void createHttpsClient() {

	logger.debug("START: createHttpsClient()");

	// Create the requestURL from the configured baseURL.
	try {
	    requestURL = new URL(baseURL);
	} catch (MalformedURLException mue) {
	    logger.error("Malformed baseURL set: " + mue);
	}

	// TODO: Allow non-JKS format certificate stores (e.g. PKCS12)

	logger.debug("Loading TrustStore from file: " + trustStorePath);
	// Load Trust Store
	trustStore = loadJKSFromFile(trustStorePath, trustStorePass);

	logger.debug("Loading KeyStore from file: " + clientKSPath);
	clientKS = loadJKSFromFile(clientKSPath, clientKSPass);


        SSLContextBuilder sslBuilder = SSLContexts.custom();

        try {
            sslBuilder.loadTrustMaterial(trustStore);
            sslBuilder.loadKeyMaterial(clientKS, clientKSPass);
        } catch (Exception e) {
            logger.error("Exception: " + e);
        }


        SSLContext sslContext = null;
        try {
            sslContext = sslBuilder.build();
        } catch (Exception e) {
            logger.error("Exception: " + e);
        }


	logger.debug("Creating client with custom SSL Context.");
	logger.debug("Client will be created with " + maxConnectionsPerRoute + " max connections per route");

        client = HttpClients.custom()
                .setSslcontext(sslContext)
                .setMaxConnPerRoute(maxConnectionsPerRoute)
                .build();
	logger.debug("END: createHttpsClient()");

    }
    
    protected URI appendPathToRequestURL(String pathToAppend) {
	URI updatedURI = null;
	try {
	    updatedURI = new URI(requestURL.getProtocol(),
				 requestURL.getAuthority(),
				 requestURL.getPath() + pathToAppend,
				 null,
				 null);
	} catch (URISyntaxException uriSE) {
	    logger.error("Invalid Syntax encountered while attempting to append path to baseURL: " + uriSE);
	}
	return updatedURI;
    }

    protected URI getRemoteUserUri(String username) throws UnsupportedEncodingException {
	return appendPathToRequestURL("/" + username + "/info");
    }

    protected URI getRemoteUserGroupsUri(String username) throws UnsupportedEncodingException {
	return appendPathToRequestURL("/" + username + "/groups/" + projectName);
    }

    public JSONObject retrieveRemoteUserDetails(String username) throws Exception {

	logger.debug("START: retrieveRemoteUserDetails()");
	logger.debug("[arg] username: " + username);

	JSONObject data = null;

        HttpGet httpget = new HttpGet(getRemoteUserUri(username));

        CloseableHttpResponse response = client.execute(httpget);

        try {
            String contentType = response.getEntity().getContentType().getValue();

            if(response.getStatusLine().getStatusCode() != 200 || !contentType.contains("json")) {
                throw new IOException("Invalid response from server - status " + response.getStatusLine().getStatusCode() + ": " + EntityUtils.toString(response.getEntity()));
            } else {
                data = new JSONObject(response.getEntity().getContent());
                // return data;
            }
        } finally {
            response.close();
        }
	logger.debug("END: retrieveRemoteUserDetails()");
	return data;
    }

    public JSONObject retrieveRemoteUserGroups(String username) throws IOException {

	logger.debug("START: retrieveRemoteUserGroups()");
	logger.debug("[arg] username: " + username);

	JSONObject data = null;

        HttpGet httpget = new HttpGet(getRemoteUserGroupsUri(username));

        CloseableHttpResponse response = client.execute(httpget);

        try {
            String contentType = response.getEntity().getContentType().getValue();

            if (response.getStatusLine().getStatusCode() != 200 || !contentType.contains("json")) {
                throw new IOException("Invalid response from server - status " + response.getStatusLine().getStatusCode() + ": " + EntityUtils.toString(response.getEntity()));
            } else {
                data = new JSONObject(response.getEntity().getContent());
                // return data;
            }
        } finally {
            response.close();
        }
	logger.debug("END: retrieveRemoteUserGroups()");
	return data;

    }

    @PreDestroy
    public void closeHttpsClient(){
        try {
            client.close();
        } catch (IOException e ){
            logger.error("Exception: " + e);
        }
    }

    public void setKeyStorePath(String path){
        this.clientKSPath = path;
    }

    public void setTrustStorePath(String path){
        this.trustStorePath = path;
    }

    public void setKeyStorePass(String keystorepass) {
        this.clientKSPass = keystorepass.toCharArray();
    }

    public void setTrustStorePass(String truststorepass) {
	this.trustStorePass = truststorepass.toCharArray();
    }

    public void setProjectName(String projectName){
        this.projectName = projectName;
    }

    public void setMaxConnPerRoute(int maxConnections) {
	this.maxConnectionsPerRoute = maxConnections;
    }
    public void setBaseURL(String baseURL) { 
	this.baseURL = baseURL; 
    }

}
