package com.inteligr8.activiti.ais;

import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.keycloak.representations.AccessToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import com.activiti.domain.idm.Group;
import com.activiti.domain.idm.Tenant;
import com.activiti.domain.idm.User;
import com.activiti.service.api.GroupService;
import com.activiti.service.api.UserService;
import com.activiti.service.idm.TenantService;
import com.activiti.service.license.LicenseService;
import com.inteligr8.activiti.Authenticator;

/**
 * This class/bean implements an Open ID Connect authenticator for Alfresco
 * Process Services that supports the creation of missing users and groups and
 * synchronizes user/group membership.  This is configurable using several
 * Spring property values starting with the `keycloak-ext.` prefix.
 * 
 * This implements an internal Authenticator so other authenticators could be
 * created in the future.
 * 
 * FIXME This implements is not good for multi-tenancy.
 * 
 * @author brian.long@yudrio.com
 */
@Component("activiti-app.authenticator")
@Lazy
public class IdentityServiceActivitiAppAuthenticator extends AbstractIdentityServiceActivitiAuthenticator implements Authenticator {
	
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    
    private final Pattern emailNamesPattern = Pattern.compile("([A-Za-z]+)[A-Za-z0-9]*\\.([A-Za-z]+)[A-Za-z0-9]*@.*");
    private final String externalIdmSource = "ais";
    
    @Value("${keycloak-ext.createMissingUser:true}")
    private boolean createMissingUser;

    @Value("${keycloak-ext.clearNewUserGroups:true}")
    private boolean clearNewUserGroups;

    @Value("${keycloak-ext.createMissingGroup:true}")
    private boolean createMissingGroup;

    @Value("${keycloak-ext.syncGroupAdd:true}")
    private boolean syncGroupAdd;

    @Value("${keycloak-ext.syncGroupRemove:true}")
    private boolean syncGroupRemove;

    @Autowired
    private LicenseService licenseService;
    
    @Autowired
    private TenantService tenantService;
    
    @Autowired
    private UserService userService;

    @Autowired
    private GroupService groupService;
    
    /**
     * This method validates that the user exists, if not, it creates the
     * missing user.  Without this functionality, SSO straight up fails in APS.
     */
    @Override
    public void preAuthenticate(Authentication auth) throws AuthenticationException { 
    	Long tenantId = this.findDefaultTenantId();
		this.logger.trace("Tenant ID: {}", tenantId);
		
    	User user = this.findUser(auth, tenantId);
    	if (user == null) {
    		if (this.createMissingUser) {
	    		this.logger.debug("User does not yet exist; creating the user: {}", auth.getName());
	    		
	    		user = this.createUser(auth, tenantId);
	    		this.logger.debug("Created user: {} => {}", user.getId(), user.getExternalId());
	    		
	    		if (this.clearNewUserGroups) {
		    		this.logger.debug("Clearing groups: {}", user.getId());
	    			// fetch and remove default groups
	    			user = this.userService.findUserByEmailFetchGroups(user.getEmail());
	    			for (Group group : user.getGroups())
	    				this.groupService.deleteUserFromGroup(group, user);
	    		}
    		} else {
    			this.logger.info("User does not exist; user creation is disabled: {}", auth.getName());
    		}
    	}
    }
    
    /**
     * This method validates that the groups exist, if not, it creates the
     * missing ones.  Without this functionality, SSO works, but the user's
     * authorities are not synchronized.
     */
    @Override
    public void postAuthenticate(Authentication auth) throws AuthenticationException {
    	Long tenantId = this.findDefaultTenantId();
    	User user = this.findUser(auth, tenantId);
		this.logger.debug("Inspecting user: {} => {}", user.getId(), user.getExternalId());
		
    	this.syncUserAuthorities(user, auth, tenantId);
    }
    
    private Long findDefaultTenantId() {
    	String defaultTenantName = this.licenseService.getDefaultTenantName();
		this.logger.trace("Default Tenant: {}", defaultTenantName);
		
    	List<Tenant> tenants = this.tenantService.findTenantsByName(defaultTenantName);
    	if (tenants == null || tenants.isEmpty()) {
    		this.logger.warn("Default tenant not found");
    		return null;
    	}
    	
    	Tenant tenant = tenants.iterator().next();
    	return tenant.getId();
    }
    
    private User findUser(Authentication auth, Long tenantId) {
    	String email = auth.getName();
		
    	User user = this.userService.findUserByEmailAndTenantId(email, tenantId);
    	if (user == null) {
    		this.logger.debug("User does not exist in tenant; trying tenant-less lookup: {}", email);
    		user = this.userService.findUserByEmail(email);
    	} else {
    		this.logger.trace("Found user: {}", user.getId());
    	}
    	
    	return user;
    }
    
    private User createUser(Authentication auth, Long tenantId) {
		AccessToken atoken = this.getKeycloakAccessToken(auth);
		if (atoken == null) {
    		this.logger.debug("The keycloak access token could not be found; using email to determine names: {}", auth.getName());
    		Matcher emailNamesMatcher = this.emailNamesPattern.matcher(auth.getName());
    		if (!emailNamesMatcher.matches()) {
        		this.logger.warn("The email address could not be parsed for names: {}", auth.getName());
    			return this.userService.createNewUserFromExternalStore(auth.getName(), "Unknown", "User", tenantId, auth.getName(), this.externalIdmSource, new Date());
    		} else {
    			String firstName = StringUtils.capitalize(emailNamesMatcher.group(1));
    			String lastName = StringUtils.capitalize(emailNamesMatcher.group(2));
    			return this.userService.createNewUserFromExternalStore(auth.getName(), firstName, lastName, tenantId, auth.getName(), this.externalIdmSource, new Date());
    		}
		} else {
			return this.userService.createNewUserFromExternalStore(auth.getName(), atoken.getGivenName(), atoken.getFamilyName(), tenantId, auth.getName(), this.externalIdmSource, new Date());
		}
    }

    private void syncUserAuthorities(User user, Authentication auth, Long tenantId) {
    	Set<String> authorities = this.getRoles(auth);
    	if (authorities == null) {
    		this.logger.debug("The user authorities could not be determined; skipping sync: {}", user.getEmail());
    		return;
    	}
    	
		// check Activiti groups
		User userWithGroups = this.userService.findUserByEmailFetchGroups(user.getEmail());
		for (Group group : userWithGroups.getGroups()) {
			this.logger.trace("Inspecting group: {} => ", group.getId(), group.getExternalId());
			
			if (authorities.remove(group.getExternalId())) {
				// all good
			} else {
				if (this.syncGroupRemove) {
					this.logger.trace("Removing user '{}' from group '{}'", user.getExternalId(), group.getExternalId());
					this.groupService.deleteUserFromGroup(group, userWithGroups);
				} else {
					this.logger.debug("User/group membership sync disabled; not removing user from group: {} => {}", user.getExternalId(), group.getExternalId());
				}
			}
		}
		
		// add remaining authorities into Activiti
		for (String authority : authorities) {
			this.logger.trace("Syncing group membership: {}", authority);
			
			Group group = this.groupService.getGroupByExternalId(authority);
			if (group == null) {
				if (this.createMissingGroup) {
					this.logger.trace("Creating new group: {}", authority);
					String shortAuthority = authority.replaceFirst("[A-Z]+_", "");
					group = this.groupService.createGroupFromExternalStore(shortAuthority, tenantId, Group.TYPE_SYSTEM_GROUP, null, authority, new Date());
				} else {
	    			this.logger.debug("Group does not exist; group creation is disabled: {}", authority);
				}
			}

			if (group != null && this.syncGroupAdd) {
				this.logger.trace("Adding user '{}' from group '{}'", user.getExternalId(), group.getExternalId());
				this.groupService.addUserToGroup(group, userWithGroups);
			} else {
				this.logger.debug("User/group membership sync disabled; not adding user to group: {} => {}", user.getExternalId(), group.getExternalId());
			}
		}
    }
}
