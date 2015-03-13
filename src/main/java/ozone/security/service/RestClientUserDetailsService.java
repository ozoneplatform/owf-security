package ozone.security.service;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import ozone.security.authentication.OWFUserDetailsImpl;
import ozone.security.authorization.model.GrantedAuthorityImpl;
import ozone.security.authorization.target.OwfGroup;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.IOException;
import java.util.*;


public class RestClientUserDetailsService implements UserDetailsService {

    private static final Log logger = LogFactory.getLog(RestClientUserDetailsService.class);

    static final String ROLE_USER = "ROLE_USER";
    static final String ROLE_ADMIN = "ROLE_ADMIN";

    protected Map<String, GrantedAuthority> groupAuthorityMap;
    protected AuthServiceHttpClient restClient = null;

    @Cacheable(cacheName="userDetailsCache")
    public UserDetails loadUserByUsername(String username) {

        OWFUserDetailsImpl principal;

        Collection<GrantedAuthority> authorities = getUserAuthorities(username);

        principal = retrieveUser(username, authorities);

        return principal;

    }

    protected Collection<GrantedAuthority> getUserAuthorities(String username) {

        // Working with mock service
//        JSONArray resultGroups = new JSONArray();
//        resultGroups.put("CN=aml_org,OU=Ozone,O=Ozone,L=Columbia,ST=Maryland,C=US");

        JSONArray resultGroups = new JSONArray();
        try {
            resultGroups = getGroupsRestResult(username);
        } catch (JSONException e) {
            logger.error("Exception 96: " + e);
        }
        Collection<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();

        for(int i = 0; i < resultGroups.length(); i++) {
            try {
                LdapName dn = new LdapName(resultGroups.getString(i));
                for (int j = 0; j < dn.size(); j++) {
                    Rdn rdn = dn.getRdn(j);
                    if(rdn.getType().equalsIgnoreCase("cn")) {
                        String value = (String) rdn.getValue();
                        if(groupAuthorityMap.get(value) != null){
                            authorities.add(groupAuthorityMap.get(value));
                        }
                    }
                }
            } catch (Exception e) {
                logger.error("Exception 104: " + e);
            }
        }

        boolean foundRoleUser = false;
        boolean foundRoleAdmin = false;

        for(GrantedAuthority aRole: authorities) {
            if(ROLE_USER.equals(aRole.getAuthority())){
                foundRoleUser = true;
                break;
            }

            if(ROLE_ADMIN.equals(aRole.getAuthority())) {
                foundRoleAdmin = true;
                break;
            }
        }

        if(foundRoleAdmin && !foundRoleUser) {
            authorities.add(new GrantedAuthorityImpl(ROLE_USER));
        }

        return authorities;
    }


    protected OWFUserDetailsImpl retrieveUser(String uid, Collection<GrantedAuthority> authorities) {
        String emailAddress;
        String displayName;

        JSONObject response = getRestResult(uid);

        try {
            emailAddress = response.getString("email");
        } catch (JSONException e) {
            emailAddress = "";
        }

        try {
            displayName = response.getString("fullName");
        } catch (JSONException e) {
            displayName = "";
        }


        OWFUserDetailsImpl principal = new OWFUserDetailsImpl(uid, "", authorities, new ArrayList<OwfGroup>());
        principal.setEmail(emailAddress);
        principal.setDisplayName(displayName);

        return principal;

    }


    private JSONObject getRestResult(String username){
        JSONObject result = null;

        try {
            result = restClient.retrieveRemoteUserDetails(username);
        } catch (IOException e) {
            logger.error("Exception 148: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error("Exception 150: " + e.getMessage(), e);
        }

        return result;
    }

    private JSONArray getGroupsRestResult(String username) throws JSONException {
        JSONObject result = null;
	JSONArray usersGroups = null;

        try {
            result = restClient.retrieveRemoteUserGroups(username);
        } catch (IOException e) {
            logger.error("Exception: " + e.getMessage());
        } catch (Exception e) {
            logger.error("Exception: " + e.getMessage());
        }

	if (result != null) {
	    usersGroups = result.getJSONArray("groups");
	} else {
	    usersGroups = new JSONArray("[]");
	}
        return usersGroups;
    }


    public void setRestClient(AuthServiceHttpClient restClient) {
        this.restClient = restClient;
    }

    public void setGroupAuthorityMap(Map<String, String> map){
        Map temp = new HashMap<String, GrantedAuthority>(map.size(), 1);

        for(Map.Entry<String, String> entry: map.entrySet()){
            GrantedAuthority auth = new GrantedAuthorityImpl(entry.getValue());
            temp.put(entry.getKey(), auth);
        }

        this.groupAuthorityMap = Collections.unmodifiableMap(temp);
    }

}
