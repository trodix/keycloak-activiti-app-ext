/*
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package com.inteligr8.activiti;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.activiti.domain.idm.Group;
import com.activiti.domain.idm.GroupCapability;
import com.activiti.domain.idm.Tenant;
import com.activiti.service.api.GroupService;

/**
 * This class/bean attempts to fix the administrative group in APS.  This may
 * be used if your OAuth configuration leaves you without any administrative
 * groups.
 * 
 * @author brian@inteligr8.com
 */
@Component
public class ActivitiAppAdminGroupFixer implements DataFixer {
	
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    
    private final List<String> adminCapabilities = Arrays.asList(
    		"access-all-models-in-tenant",
    		"access-editor",
    		"access-reports",
    		"publish-app-to-dashboard",
    		"tenant-admin",
    		"tenant-admin-api",
    		"upload-license");
    
    @Autowired(required = false)
    private GroupService groupService;
    
    @Autowired
    private TenantFinderService tenantFinderService;
    
    @Value("${keycloak-ext.group.admins.name:admins}")
    private String adminGroupName;
    
    @Value("${keycloak-ext.group.admins.externalId:#{null}}")
    private String adminGroupExternalId;
    
    @Value("${keycloak-ext.group.admins.validate:false}")
    private boolean validateAdministratorsGroup;
    
    @Override
	public void fix() {
		this.logger.trace("fix()");
		
		if (this.logger.isTraceEnabled())
			this.logGroups();
		if (this.validateAdministratorsGroup)
			this.validateAdmins();
	}
	
	private void logGroups() {
		if (this.groupService == null)
			return;
		
		Collection<Tenant> tenants = this.tenantFinderService.getTenants();
		for (Tenant tenant : tenants) {
			this.logger.trace("Tenant: {} => {}", tenant.getId(), tenant.getName());
			this.logger.trace("Functional groups: {}", this.toGroupNames(this.groupService.getFunctionalGroups(tenant.getId())));
			this.logger.trace("System groups: {}", this.toGroupNames(this.groupService.getSystemGroups(tenant.getId())));
		}
		
		this.logger.trace("Tenant: null");
		this.logger.trace("Functional groups: {}", this.toGroupNames(this.groupService.getFunctionalGroups(null)));
		this.logger.trace("System groups: {}", this.toGroupNames(this.groupService.getSystemGroups(null)));
	}
	
	private void validateAdmins() {
		if (this.groupService == null)
			return;
		
    	Long tenantId = this.tenantFinderService.findTenantId();
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
	
	private Collection<String> toGroupNames(Collection<Group> groups) {
		List<String> groupNames = new ArrayList<>(groups.size());
		for (Group group : groups)
			groupNames.add(group.getName() + " [" + group.getExternalId() + "]");
		return groupNames;
	}

}
