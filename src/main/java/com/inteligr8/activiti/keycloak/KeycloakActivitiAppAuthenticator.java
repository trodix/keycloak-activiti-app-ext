package com.inteligr8.activiti.keycloak;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.persistence.NonUniqueResultException;

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
import com.activiti.domain.idm.User;
import com.activiti.service.api.GroupService;
import com.activiti.service.api.UserService;
import com.inteligr8.activiti.TenantFinderService;

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
@Component("keycloak-ext.activiti-app.authenticator")
@Lazy
public class KeycloakActivitiAppAuthenticator extends AbstractKeycloakActivitiAuthenticator {
	
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    
    private final Pattern emailNamesPattern = Pattern.compile("([A-Za-z]+)[A-Za-z0-9]*\\.([A-Za-z]+)[A-Za-z0-9]*@.*");
    
    @Autowired
    private UserService userService;

    @Autowired
    private GroupService groupService;
    
    @Autowired
    private TenantFinderService tenantFinderService;
    
    @Value("${keycloak-ext.external.id:ais}")
    protected String externalIdmSource;

    @Value("${keycloak-ext.syncGroupAs:organization}")
    protected String syncGroupAs;
    
    protected boolean syncGroupAsOrganization() {
    	return !this.syncGroupAsCapability();
    }
    
    protected boolean syncGroupAsCapability() {
    	return this.syncGroupAs != null && this.syncGroupAs.toLowerCase().startsWith("cap");
    }
    
    /**
     * This method validates that the user exists, if not, it creates the
     * missing user.  Without this functionality, SSO straight up fails in APS.
     */
    @Override
    public void preAuthenticate(Authentication auth) throws AuthenticationException { 
    	Long tenantId = this.tenantFinderService.findTenantId();
		this.logger.trace("Tenant ID: {}", tenantId);
		
    	User user = this.findUser(auth, tenantId);
    	if (user == null) {
    		if (this.createMissingUser) {
	    		this.logger.debug("User does not yet exist; creating the user: {}", auth.getName());
	    		
	    		user = this.createUser(auth, tenantId);
	    		this.logger.debug("Created user: {} => {}", user.getId(), user.getExternalId());
	    		
	    		if (this.clearNewUserDefaultGroups) {
		    		this.logger.debug("Clearing groups: {}", user.getId());
	    			// fetch and remove default groups
	    			user = this.userService.getUser(user.getId(), true);
	    			for (Group group : user.getGroups())
	    				this.groupService.deleteUserFromGroup(group, user);
	    		}
    		} else {
    			this.logger.info("User does not exist; user creation is disabled: {}", auth.getName());
    		}
    	} else if (user.getExternalOriginalSrc() == null || user.getExternalOriginalSrc().length() == 0) {
    		this.logger.debug("User exists, but not created by an external source: {}", auth.getName());
    		this.logger.info("Linking user '{}' with external IDM '{}'", auth.getName(), this.externalIdmSource);
    		user.setExternalId(auth.getName());
    		user.setExternalOriginalSrc(this.externalIdmSource);
    		this.userService.save(user);
    	} else if (!this.externalIdmSource.equals(user.getExternalOriginalSrc())) {
    		this.logger.debug("User '{}' exists, but created by another source: {}", auth.getName(), user.getExternalOriginalSrc());
    	} else {
    		this.logger.trace("User already exists: {}", auth.getName());
    	}
    }
    
    /**
     * This method validates that the groups exist, if not, it creates the
     * missing ones.  Without this functionality, SSO works, but the user's
     * authorities are not synchronized.
     */
    @Override
    public void postAuthenticate(Authentication auth) throws AuthenticationException {
    	Long tenantId = this.tenantFinderService.findTenantId();
    	User user = this.findUser(auth, tenantId);
		this.logger.debug("Inspecting user: {} => {}", user.getId(), user.getExternalId());
		
    	this.syncUserRoles(user, auth, tenantId);
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
    			return this.userService.createNewUserFromExternalStore(auth.getName(), "Unknown", "Person", tenantId, auth.getName(), this.externalIdmSource, new Date());
    		} else {
    			String firstName = StringUtils.capitalize(emailNamesMatcher.group(1));
    			String lastName = StringUtils.capitalize(emailNamesMatcher.group(2));
    			return this.userService.createNewUserFromExternalStore(auth.getName(), firstName, lastName, tenantId, auth.getName(), this.externalIdmSource, new Date());
    		}
		} else {
			return this.userService.createNewUserFromExternalStore(auth.getName(), atoken.getGivenName(), atoken.getFamilyName(), tenantId, auth.getName(), this.externalIdmSource, new Date());
		}
    }

    private void syncUserRoles(User user, Authentication auth, Long tenantId) {
    	Map<String, String> roles = this.getKeycloakRoles(auth);
    	if (roles == null) {
    		this.logger.debug("The user roles could not be determined; skipping sync: {}", user.getEmail());
    		return;
    	}
    	
    	boolean syncAsOrg = this.syncGroupAsOrganization();
    	
		// check Activiti groups
		User userWithGroups = this.userService.getUser(user.getId(), true);
		for (Group group : userWithGroups.getGroups()) {
			if (group.getExternalId() == null && !this.syncInternalGroups)
				continue;
			
			this.logger.trace("Inspecting group: {} => {} ({})", group.getId(), group.getName(), group.getExternalId());
			
			if (group.getExternalId() != null && this.removeMapEntriesByValue(roles, this.apsGroupExternalIdToKeycloakRole(group.getExternalId()))) {
				if (group.getTenantId() == null) {
					// fix stray groups
					group.setTenantId(tenantId);
					group.setLastUpdate(new Date());
					this.groupService.save(group);
				}
				// role already existed and the user is already a member
			} else if (group.getExternalId() == null && roles.remove(this.apsGroupNameToKeycloakRole(group.getName())) != null) {
				// register the group as external
				group.setExternalId(this.keycloakRoleToApsGroupExternalId(this.apsGroupNameToKeycloakRole(group.getName())));
				group.setLastUpdate(new Date());
				this.groupService.save(group);
				// internal role already existed and the user is already a member
			} else {
				// at this point, we have a group that the user does not have a corresponding role for
				if (this.syncGroupRemove) {
					this.logger.trace("Removing user '{}' from group '{}'", user.getExternalId(), group.getName());
					this.groupService.deleteUserFromGroup(group, userWithGroups);
				} else {
					this.logger.debug("User/group membership sync disabled; not removing user from group: {} => {}", user.getExternalId(), group.getName());
				}
			}
		}
		
		// add remaining authorities into Activiti
		for (Entry<String, String> role : roles.entrySet()) {
			this.logger.trace("Syncing group membership: {}", role);
			
			Group group;
			try {
				group = this.groupService.getGroupByExternalIdAndTenantId(this.keycloakRoleToApsGroupExternalId(role.getKey()), tenantId);
			} catch (NonUniqueResultException nure) {
				this.logger.warn("There are multiple groups with the external ID; not adding user to group: {}", role.getKey());
				continue;
			}

			if (group == null && this.syncInternalGroups) {
				List<Group> groups = this.groupService.getGroupByNameAndTenantId(this.keycloakRoleToApsGroupName(role.getValue()), tenantId);
				if (groups.size() > 1) {
					this.logger.warn("There are multiple groups with the same name; not adding user to group: {}", role.getValue());
					continue;
				} else if (groups.size() == 1) {
					group = groups.iterator().next();
					this.logger.debug("Found an internal group; registering as external: {}", group.getName());
					group.setExternalId(this.keycloakRoleToApsGroupExternalId(role.getKey()));
					group.setLastSyncTimeStamp(new Date());
					group.setLastUpdate(new Date());
					this.groupService.save(group);
				}
			}
			
			if (group == null) {
				if (this.createMissingGroup) {
					this.logger.trace("Creating new group for role: {}", role);
					String name = this.keycloakRoleToApsGroupName(role.getValue());
					String externalId = this.keycloakRoleToApsGroupExternalId(role.getKey());
					int type = syncAsOrg ? Group.TYPE_FUNCTIONAL_GROUP : Group.TYPE_SYSTEM_GROUP;
					this.logger.trace("Creating new group: {} ({}) [type: {}]", name, externalId, type);
					group = this.groupService.createGroupFromExternalStore(name, tenantId, type, null, externalId, new Date());
				} else {
	    			this.logger.debug("Group does not exist; group creation is disabled: {}", role);
				}
			}

			if (group != null && this.syncGroupAdd) {
				this.logger.trace("Adding user '{}' to group '{}'", user.getExternalId(), group.getName());
				this.groupService.addUserToGroup(group, userWithGroups);
			} else {
				this.logger.debug("User/group membership sync disabled; not adding user to group: {} => {}", user.getExternalId(), group.getName());
			}
		}
    }
    
    private String keycloakRoleToApsGroupExternalId(String role) {
    	return this.externalIdmSource + "_" + role;
    }
    
    private String apsGroupExternalIdToKeycloakRole(String externalId) {
    	int underscorePos = externalId.indexOf('_');
    	return underscorePos < 0 ? externalId : externalId.substring(underscorePos + 1);
    }
    
    private String keycloakRoleToApsGroupName(String role) {
    	return role;
    }
    
    private String apsGroupNameToKeycloakRole(String externalId) {
    	return externalId;
    }
    
}
