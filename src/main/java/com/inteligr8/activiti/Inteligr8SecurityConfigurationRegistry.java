package com.inteligr8.activiti;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import com.activiti.api.security.AlfrescoSecurityConfigOverride;
import com.activiti.domain.idm.Group;
import com.activiti.domain.idm.Tenant;
import com.activiti.service.api.GroupService;
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
    
    @Autowired
    private List<ActivitiSecurityConfigAdapter> adapters;
    
    @Autowired(required = false)
    private LicenseService licenseService;
    
    @Autowired(required = false)
    private TenantService tenantService;
    
    @Autowired(required = false)
    private GroupService groupService;
	
	@Override
	public void configureGlobal(AuthenticationManagerBuilder authmanBuilder, UserDetailsService userDetailsService) {
		this.logger.trace("configureGlobal()");
		
		Collections.sort(this.adapters);
		
		if (this.logger.isTraceEnabled())
			this.logGroups();
		
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
		Long tenantId = this.findDefaultTenantId();
		if (tenantId != null) {
			// not first boot
			this.logger.trace("Functional groups: {}", this.toGroupNames(this.groupService.getFunctionalGroups(tenantId)));
			this.logger.trace("System groups: {}", this.toGroupNames(this.groupService.getSystemGroups(tenantId)));
		}
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
	
	private Collection<String> toGroupNames(Collection<Group> groups) {
		List<String> groupNames = new ArrayList<>(groups.size());
		for (Group group : groups)
			groupNames.add(group.getName() + " [" + group.getExternalId() + "]");
		return groupNames;
	}

}
