package com.inteligr8.activiti;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import com.activiti.api.security.AlfrescoSecurityConfigOverride;
import com.activiti.domain.idm.Group;
import com.activiti.domain.idm.GroupCapability;
import com.activiti.domain.idm.Tenant;
import com.activiti.domain.idm.User;
import com.activiti.service.api.GroupService;
import com.activiti.service.api.UserService;
import com.activiti.service.idm.TenantService;
import com.activiti.service.license.LicenseService;

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
public class Inteligr8SecurityConfigurationRegistry implements AlfrescoSecurityConfigOverride {
	
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    
    private final List<String> adminCapabilities = Arrays.asList(
    		"access-all-models-in-tenant",
    		"access-editor",
    		"access-reports",
    		"publish-app-to-dashboard",
    		"tenant-admin",
    		"tenant-admin-api",
    		"upload-license");
    
    @Autowired
    private List<ActivitiSecurityConfigAdapter> adapters;
    
    @Autowired(required = false)
    private LicenseService licenseService;
    
    @Autowired(required = false)
    private TenantService tenantService;
    
    @Autowired(required = false)
    private UserService userService;
    
    @Autowired(required = false)
    private GroupService groupService;
    
    @Value("${keycloak-ext.tenant:#{null}}")
    private String tenant;
    
    @Value("${keycloak-ext.default.admins.users:#{null}}")
    private String adminUserStrs;
    
    @Value("${keycloak-ext.group.admins.name:admins}")
    private String adminGroupName;
    
    @Value("${keycloak-ext.group.admins.externalId:#{null}}")
    private String adminGroupExternalId;
    
    @Value("${keycloak-ext.group.admins.validate:false}")
    private boolean validateAdministratorsGroup;
	
	@Override
	public void configureGlobal(AuthenticationManagerBuilder authmanBuilder, UserDetailsService userDetailsService) {
		this.logger.trace("configureGlobal()");
		
		Collections.sort(this.adapters);
		
		if (this.logger.isTraceEnabled())
			this.logGroups();
		if (this.validateAdministratorsGroup)
			this.validateAdmins();
    	if (this.adminUserStrs != null && this.adminUserStrs.length() > 0)
    		this.associateAdmins();
		
		for (ActivitiSecurityConfigAdapter adapter : this.adapters) {
			if (adapter.isEnabled()) {
				this.logger.info("Security adapter enabled: {}", adapter.getClass());
				adapter.configureGlobal(authmanBuilder, userDetailsService);
				break;
			} else {
				this.logger.info("Security adapter disabled: {}", adapter.getClass());
			}
		}
	}
	
	private void logGroups() {
		if (this.groupService == null)
			return;
		
		List<Object[]> tenantObjs = this.tenantService.getAllTenants();
		for (Object[] tenantObj : tenantObjs) {
			Long tenantId = (Long)tenantObj[0];
			if (tenantId != null) {
				Tenant tenant = this.tenantService.getTenant(tenantId);
				this.logger.trace("Tenant: {} => {}", tenantId, tenant.getName());
				this.logger.trace("Functional groups: {}", this.toGroupNames(this.groupService.getFunctionalGroups(tenantId)));
				this.logger.trace("System groups: {}", this.toGroupNames(this.groupService.getSystemGroups(tenantId)));
			}
		}
	}
	
	private void validateAdmins() {
		if (this.groupService == null)
			return;
		
    	Long tenantId = this.findTenantId();
		Group group = this.groupService.getGroupByExternalIdAndTenantId(this.adminGroupExternalId, tenantId);
		if (group == null) {
			List<Group> groups = this.groupService.getGroupByNameAndTenantId(this.adminGroupName, tenantId);
			if (!groups.isEmpty())
				group = groups.iterator().next();
		}

		if (group == null) {
			this.logger.info("Creating group: {} ({})", this.adminGroupName, this.adminGroupExternalId);
			if (this.adminGroupExternalId != null) {
				group = this.groupService.createGroupFromExternalStore(
						this.adminGroupExternalId, tenantId, Group.TYPE_SYSTEM_GROUP, null, this.adminGroupName, new Date());
			} else {
				group = this.groupService.createGroup(this.adminGroupName, tenantId, Group.TYPE_SYSTEM_GROUP, null);
			}
		}

		this.logger.debug("Checking group capabilities: {}", group.getName());
		Group groupWithCaps = this.groupService.getGroup(group.getId(), false, true, false, false);
		Set<String> adminCaps = new HashSet<>(this.adminCapabilities);
		for (GroupCapability cap : groupWithCaps.getCapabilities())
			adminCaps.remove(cap.getName());
		if (!adminCaps.isEmpty()) {
			this.logger.info("Granting group '{}' capabilities: {}", group.getName(), adminCaps);
			this.groupService.addCapabilitiesToGroup(group.getId(), new ArrayList<>(adminCaps));
		}
	}
	
	private void associateAdmins() {
		if (this.userService == null || this.groupService == null)
			return;
		
		List<String> adminUsers = Arrays.asList(this.adminUserStrs.split(","));
		if (adminUsers.isEmpty())
			return;

    	Long tenantId = this.findTenantId();
    	List<Group> groups;
		Group group1 = this.groupService.getGroupByExternalIdAndTenantId(this.adminGroupExternalId, tenantId);
		if (group1 != null) {
			groups = Arrays.asList(group1);
		} else {
			groups = this.groupService.getGroupByNameAndTenantId(this.adminGroupName, tenantId);
		}
		this.logger.debug("Found {} admin group(s)", groups.size());
		
		for (String email : adminUsers) {
    		User user = this.userService.findUserByEmail(email);

    		this.logger.debug("Adding {} to admin group(s)", user.getEmail());
    		for (Group group : groups)
    			this.groupService.addUserToGroup(group, user);
		}
	}
    
    private Long findTenantId() {
    	String tenantName = this.tenant == null ? this.licenseService.getDefaultTenantName() : this.tenant;
		this.logger.trace("Using Tenant: {}", tenantName);
		
    	List<Tenant> tenants = this.tenantService.findTenantsByName(tenantName);
    	if (tenants == null || tenants.isEmpty()) {
    		this.logger.warn("Default tenant not found");
    		return null;
    	}
    	
    	Tenant tenant = tenants.iterator().next();
    	return tenant.getId();
    }
	
	private Collection<String> toGroupNames(Collection<Group> groups) {
		List<String> groupNames = new ArrayList<>(groups.size());
		for (Group group : groups)
			groupNames.add(group.getName() + " [" + group.getExternalId() + "]");
		return groupNames;
	}

}
