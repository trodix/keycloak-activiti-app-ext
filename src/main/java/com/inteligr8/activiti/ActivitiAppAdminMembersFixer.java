package com.inteligr8.activiti;

import java.util.Arrays;
import java.util.List;

import javax.persistence.NonUniqueResultException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.activiti.domain.idm.Group;
import com.activiti.domain.idm.User;
import com.activiti.service.api.GroupService;
import com.activiti.service.api.UserService;

/**
 * This class/bean overrides the APS security configuration with a collection
 * of implementations.  The OOTB extension only provides one override.  This
 * uses that extension point, but delegates it out to multiple possible
 * implementations.
 * 
 * Order cannot be controlled, so it should not be assumed in any adapter
 * implementation.
 * 
 * @author brian@inteligr8.com
 */
@Component
public class ActivitiAppAdminMembersFixer implements DataFixer {
	
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    
    @Autowired(required = false)
    private UserService userService;
    
    @Autowired(required = false)
    private GroupService groupService;
    
    @Autowired
    private TenantFinderService tenantFinderService;
    
    @Value("${keycloak-ext.default.admins.users:#{null}}")
    private String adminUserStrs;
    
    @Value("${keycloak-ext.group.admins.name:admins}")
    private String adminGroupName;
    
    @Value("${keycloak-ext.group.admins.externalId:#{null}}")
    private String adminGroupExternalId;
    
    @Override
	public void fix() {
		this.logger.trace("fix()");
		
    	if (this.adminUserStrs != null && this.adminUserStrs.length() > 0)
    		this.associateAdmins();
	}
	
	private void associateAdmins() {
		if (this.userService == null || this.groupService == null)
			return;
		
		List<String> adminUsers = Arrays.asList(this.adminUserStrs.split(","));
		if (adminUsers.isEmpty())
			return;

    	Long tenantId = this.tenantFinderService.findTenantId();
    	List<Group> groups = null;
    	try {
			Group group1 = this.groupService.getGroupByExternalIdAndTenantId(this.adminGroupExternalId, tenantId);
			if (group1 != null)
				groups = Arrays.asList(group1);
    	} catch (NonUniqueResultException nure) {
    		// suppress
    	}
		if (groups == null)
			groups = this.groupService.getGroupByNameAndTenantId(this.adminGroupName, tenantId);
		
		this.logger.debug("Found {} admin group(s)", groups.size());
		
		for (String email : adminUsers) {
    		User user = this.userService.findUserByEmailAndTenantId(email, tenantId);
    		if (user == null) {
    			this.logger.info("The user with email '{}' does not exist, so they cannot be added as an administrator", email);
    		} else {
	    		this.logger.debug("Adding {} to admin group(s)", user.getEmail());
	    		for (Group group : groups)
	    			this.groupService.addUserToGroup(group, user);
    		}
		}
	}

}
