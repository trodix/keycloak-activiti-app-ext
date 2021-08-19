package com.inteligr8.activiti.keycloak;

import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.activiti.engine.IdentityService;
import org.activiti.engine.identity.Group;
import org.activiti.engine.identity.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

/**
 * This is an unused implementation for non-APS installation.  It is not tested
 * and probably pointless.
 * 
 * @author brian.long@yudrio.com
 */
@Component("keycloak-ext.activiti-engine.authenticator")
@Lazy
public class KeycloakActivitiEngineAuthenticator extends AbstractKeycloakActivitiAuthenticator {
	
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    
    @Autowired
    private IdentityService identityService;
    
    @Value("${keycloak-ext.group.prefix:KEYCLOAK_}")
    private String groupPrefix;

    /**
     * This method validates that the user exists, if not, it creates the
     * missing user.  Without this functionality, SSO straight up fails.
     */
    @Override
    public void preAuthenticate(Authentication auth) throws AuthenticationException {
    	User user = this.findUser(auth);
    	if (user == null) {
    		if (this.createMissingUser) {
    			this.logger.debug("User does not yet exist; creating the user: {}", auth.getName());

        		user = this.createUser(auth);
	    		this.logger.debug("Created user: {} => {}", user.getId(), user.getEmail());
        		
        		if (this.clearNewUserGroups) {
		    		this.logger.debug("Clearing groups: {}", user.getId());
	        		List<Group> groups = this.identityService.createGroupQuery()
	        				.groupMember(user.getId())
	        				.list();
	        		for (Group group : groups)
	        			this.identityService.deleteMembership(user.getId(), group.getId());
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
    	User user = this.findUser(auth);
		this.logger.debug("Inspecting user: {} => {}", user.getId(), user.getEmail());
		
    	this.syncUserRoles(user, auth);
    }
    
    private User findUser(Authentication auth) {
    	String email = auth.getName();
    	
    	User user = this.identityService.createUserQuery()
    			.userEmail(email)
    			.singleResult();
    	
    	return user;
    }
    
    private User createUser(Authentication auth) {
    	User user = this.identityService.newUser(auth.getName());
    	user.setEmail(auth.getName());
    	this.identityService.saveUser(user);
    	return user;
    }

    private void syncUserRoles(User user, Authentication auth) {
    	Map<String, String> roles = this.getRoles(auth);
    	if (roles == null) {
    		this.logger.debug("The user roles could not be determined; skipping sync: {}", user.getEmail());
    		return;
    	}
    	
		// check Activiti groups
    	List<Group> groups = this.identityService.createGroupQuery()
    			.groupMember(user.getEmail())
    			.list();
		this.logger.debug("User is currently a member of {} groups", groups.size());
    	for (Group group : groups) {
    		if (!group.getId().startsWith(this.groupPrefix))
    			continue;
    		
    		this.logger.trace("Inspecting group: {} => {} ({})", group.getId(), group.getName(), group.getType());
    		if (roles.remove(group.getId().substring(this.groupPrefix.length())) != null) {
        		this.logger.trace("Group and membership already exist: {} => {}", user.getEmail(), group.getName());
    			// already a member of the group
    		} else {
    			if (this.syncGroupRemove) {
	        		this.logger.trace("Group membership not in OIDC token; removing from group: {} => {}", user.getEmail(), group.getName());
	    			this.identityService.deleteMembership(user.getId(), group.getId());
    			} else {
    				this.logger.debug("User/group membership sync disabled; not removing user from group: {} => {}", user.getId(), group.getId());
    			}
    		}
    	}

		this.logger.debug("Unaddressed OIDC roles: {}", roles);
    	
    	// check remainder/unaddressed roles
    	for (Entry<String, String> role : roles.entrySet()) {
    		this.logger.trace("Inspecting role: {}", role);
    		
    		Group group = this.identityService.createGroupQuery()
    				.groupId(this.groupPrefix + role.getKey())
    				.singleResult();
    		if (group == null) {
    			if (this.createMissingGroup) {
	        		this.logger.trace("Group does not exist; creating one");
	        		group = this.identityService.newGroup(this.groupPrefix + role.getKey());
	        		group.setName(role.getValue());
	        		this.identityService.saveGroup(group);
    			} else {
        			this.logger.info("User does not exist; user creation is disabled: {}", auth.getName());
    			}
    		}

    		if (group != null && this.syncGroupAdd) {
	    		this.logger.trace("Group membership not in Activiti; adding to group: {} => {}", user.getEmail(), group.getName());
	    		this.identityService.createMembership(user.getId(), group.getId());
			} else {
				this.logger.debug("User/group membership sync disabled; not adding user to group: {} => {}", user.getId(), group.getId());
    		}
    	}
    }
    
}
