package com.inteligr8.activiti.ais;

import java.util.List;
import java.util.Set;

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

import com.inteligr8.activiti.Authenticator;

/**
 * This is an unused implementation for non-APS installation.  It is not tested
 * and probably pointless.
 * 
 * @author brian.long@yudrio.com
 */
@Component("activiti.authenticator")
@Lazy
public class IdentityServiceActivitiEngineAuthenticator extends AbstractIdentityServiceActivitiAuthenticator implements Authenticator {
	
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    
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
    private IdentityService identityService;

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
		
    	this.syncUserAuthorities(user, auth);
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

    private void syncUserAuthorities(User user, Authentication auth) {
    	Set<String> authorities = this.toSet(auth.getAuthorities());
		this.logger.debug("OIDC authorities: {}", authorities);
    	
		// check Activiti groups
    	List<Group> groups = this.identityService.createGroupQuery()
    			.groupMember(user.getEmail())
    			.list();
		this.logger.debug("User is currently a member of {} groups", groups.size());
    	for (Group group : groups) {
    		this.logger.trace("Inspecting group: {} => {} ({})", group.getId(), group.getName(), group.getType());
    		if (authorities.remove(group.getName())) {
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

		this.logger.debug("Unaddressed OIDC authorities: {}", authorities);
    	
    	// check remainder/unaddressed authorities
    	for (String authority : authorities) {
    		this.logger.trace("Inspecting authority: {}", authority);
    		
    		Group group = this.identityService.createGroupQuery()
    				.groupName(authority)
    				.singleResult();
    		if (group == null) {
    			if (this.createMissingGroup) {
	        		this.logger.trace("Group does not exist; creating one");
	        		group = this.identityService.newGroup(authority);
	        		group.setName(authority);
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
