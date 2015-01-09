package ozone.security.service;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import ozone.security.authentication.OWFUserDetails;
import ozone.security.authentication.OWFUserDetailsImpl;
import ozone.security.authorization.model.GrantedAuthorityImpl;
import ozone.security.authorization.target.OwfGroup;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import java.io.IOException;
import java.util.*;


public abstract class RestClientUserDetailsService implements UserDetailsService {

    private static final Log logger = LogFactory.getLog(RestClientUserDetailsService.class);

    static final String ROLE_USER = "ROLE_USER";
    static final String ROLE_ADMIN = "ROLE_ADMIN";
    protected Map<String, GrantedAuthority> groupAuthorityMap;


    // Need to implement RestClient
    protected AuthServiceHttpClient restClient = null;

    public UserDetails loadByUsername(String username) throws JSONException {

        OWFUserDetails principal;
        String storageUserName = null;
        String uid = username;

        Collection<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        Collection<OwfGroup> groups = new ArrayList<OwfGroup>();

        OWFUserDetailsImpl temp = new OWFUserDetailsImpl(storageUserName, "", authorities, groups);

        retrieveUser(temp, uid);


        JSONObject resultGroups = getGroupsRestResult(username);
        Collection<String> userGroups = null;

        for(String group: (Collection<String>) resultGroups.get("groups")){
            try {
                LdapName dn = new LdapName(group);
                for (int i = 0; i < dn.size(); i++){
                    if(dn.get(i).startsWith("cn=")){
                        userGroups.add(dn.get(i).substring(3));
                    }
                }
            } catch (InvalidNameException e) {
                logger.error("Exception: " + e);
            }

        }

        for(String group: userGroups){
            if(groupAuthorityMap.get(group) != null){
                addGrantedAuthority(temp, groupAuthorityMap.get(group));
            }
        }

        temp.setDisplayName(temp.getEmail());

        principal = doesUserGetAccess(temp);

        return principal;

    }

    protected OWFUserDetailsImpl doesUserGetAccess(OWFUserDetailsImpl principal){
        if(principal.getAuthorities().isEmpty()){
            return principal;
        }

        boolean foundRoleUser = false;
        boolean foundRoleAdmin = false;

        for(GrantedAuthority aRole : principal.getAuthorities()) {
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
            return addGrantedAuthority(principal, new GrantedAuthorityImpl(ROLE_USER));
        }

        return principal;
    }


    protected void retrieveUser(OWFUserDetailsImpl details, String uid) {
        String emailAddress = null;
        String username = details.getUsername();

        JSONObject response = getRestResult(username);

        try {
            emailAddress = response.getString("email");
        } catch (JSONException e) {
            logger.error("Exception: " + e);
        }

        if(emailAddress == null){
            emailAddress = uid + "@unknown.com";
        }

        details.setEmail(emailAddress);

    }


    private JSONObject getRestResult(String username){
        JSONObject result = null;

        try {
            result = restClient.retrieveRemoteUserDetails(username);
        } catch (IOException e) {
            logger.error("Exception: " + e.getMessage());
        } catch (Exception e) {
            logger.error("Exception: " + e.getMessage());
        }

        return result;
    }

    private JSONObject getGroupsRestResult(String username){
        JSONObject result = null;

        try {
            result = restClient.retrieveRemoteUserGroups(username);
        } catch (IOException e) {
            logger.error("Exception: " + e.getMessage());
        } catch (Exception e) {
            logger.error("Exception: " + e.getMessage());
        }

        return result;
    }

    public AuthServiceHttpClient getRestClient() {
        return restClient;
    }

    public void setRestClient(AuthServiceHttpClient restClient) {
        this.restClient = restClient;
    }

    public Map<String, GrantedAuthority> getGroupAuthorityMap() {
        return groupAuthorityMap;
    }

    static protected OWFUserDetailsImpl addGrantedAuthority(OWFUserDetailsImpl principal, GrantedAuthority auth) {
        Collection<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();

        for(GrantedAuthority granted : principal.getAuthorities()){
            authorities.add(granted);
        }

        authorities.add(auth);

        return new OWFUserDetailsImpl(principal.getUsername(), principal.getPassword(), authorities, principal.getOwfGroups());
    }

    public void setGroupAuthorityMap(Map<String, String> map){
        for(Map.Entry<String, String> entry: map.entrySet()){
            GrantedAuthority auth = new GrantedAuthorityImpl(entry.getValue());
            this.groupAuthorityMap.put(entry.getKey(), auth);
        }
    }

}
