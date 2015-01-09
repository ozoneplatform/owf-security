package ozone.security.service;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
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
import java.net.URI;
import java.security.KeyStore;

public class AuthServiceHttpClient {
    protected KeyStore trustStore;
    protected KeyStore keyStore;
    protected String trustStorePath;
    protected String keyStorePath;
    protected char[] keyStorePass;
    private String baseURL;
    private String projectName;
    private CloseableHttpClient client;


    private static final Log logger = LogFactory.getLog(RestClientUserDetailsService.class);


    @PostConstruct
    public void createHttpsClient() {


        char[] passwordArray = keyStorePass;

        if(trustStorePath != null) {
            FileInputStream trustStoreStream = null;
            try {
                trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
                trustStoreStream = new FileInputStream(new File(trustStorePath));
            } catch (Exception e) {
                logger.error("Exception: " + e);
            } finally {
                if(trustStoreStream != null) {
                    try {
                        trustStoreStream.close();
                    } catch (IOException e){
                        logger.error("Exception: " + e);
                    }

                }
            }
        }

        if(keyStorePath != null) {
            FileInputStream keyStoreStream = null;
            try {
                keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                keyStoreStream = new FileInputStream(new File(keyStorePath));
            } catch (Exception e) {
                logger.error("Exception: " + e);
            } finally {
                if(keyStoreStream != null) {
                    try {
                        keyStoreStream.close();
                    } catch (IOException e){
                        logger.error("Exception: " + e);
                    }

                }
            }
        }

        SSLContextBuilder sslBuilder = SSLContexts.custom();

        try {
            sslBuilder.loadTrustMaterial(trustStore);
            sslBuilder.loadKeyMaterial(keyStore, passwordArray);
        } catch (Exception e) {
            logger.error("Exception: " + e);
        }


        SSLContext sslContext = null;
        try {
            sslContext = sslBuilder.build();
        } catch (Exception e) {
            logger.error("Exception: " + e);
        }


        client = HttpClients.custom()
                .setSslcontext(sslContext)
                .build();
    }
    
    protected URI getRemoteUserUri(String username) {
        return URI.create(baseURL + "/" + username);
    }

    protected URI getRemoteUserGroupsUri(String username){
        return URI.create(baseURL + "/" + username + "/groups/" + projectName );
    }

    public JSONObject retrieveRemoteUserDetails(String username) throws IOException {

        HttpGet httpget = new HttpGet(getRemoteUserUri(username));

        CloseableHttpResponse response = client.execute(httpget);

        try {
            String contentType = response.getEntity().getContentType().getValue();

            if(response.getStatusLine().getStatusCode() != 200 || !contentType.contains("json")) {
                throw new IOException("Invalid response from server - status " + response.getStatusLine().getStatusCode() + ": " + EntityUtils.toString(response.getEntity()));
            } else {
                JSONObject data = new JSONObject(response);

                return data;
            }
        } finally {
            response.close();
        }

    }

    public JSONObject retrieveRemoteUserGroups(String username) throws IOException {

        HttpGet httpget = new HttpGet(getRemoteUserGroupsUri(username));

        CloseableHttpResponse response = client.execute(httpget);

        try {
            String contentType = response.getEntity().getContentType().getValue();

            if (response.getStatusLine().getStatusCode() != 200 || !contentType.contains("json")) {
                throw new IOException("Invalid response from server - status " + response.getStatusLine().getStatusCode() + ": " + EntityUtils.toString(response.getEntity()));
            } else {
                JSONObject data = new JSONObject(response);

                return data;
            }
        } finally {
            response.close();
        }
        
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
        this.keyStorePath = path;
    }

    public void setTrustStorePath(String path){
        this.trustStorePath = path;
    }

    public void setKeyStore(KeyStore keystore){
        this.keyStore = keystore;
    }

    public void setTrustStore(KeyStore truststore) {
        this.trustStore = truststore;
    }

    public void setKeyStorePass(String keystorepass) {
        this.keyStorePass = keystorepass.toCharArray();
    }

    public void setProjectName(String projectName){
        this.projectName = projectName;
    }

}
