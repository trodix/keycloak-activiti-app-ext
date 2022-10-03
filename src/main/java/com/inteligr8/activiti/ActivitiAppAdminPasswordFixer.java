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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.activiti.domain.idm.User;
import com.activiti.service.api.UserService;

/**
 * This class/bean attempts to reset the configured user's password.
 * 
 * @author brian@inteligr8.com
 */
@Component
public class ActivitiAppAdminPasswordFixer implements DataFixer {
	
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    
    @Autowired(required = false)
    private UserService userService;
    
    @Autowired
    private TenantFinderService tenantFinderService;

    @Value("${keycloak-ext.reset.admin.username:admin@app.activiti.com}")
    private String adminUsername;
    
    @Value("${keycloak-ext.reset.admin.password:#{null}}")
    private String adminPassword;
    
    @Override
	public void fix() {
		this.logger.trace("fix()");
		
		if (this.adminPassword != null) {
			this.logger.info("Resetting the password for admin user '{}'", this.adminUsername);
			
			Long tenantId = this.tenantFinderService.findTenantId();
			User adminUser = this.userService.findUserByEmailAndTenantId(this.adminUsername, tenantId);
			this.userService.changePassword(adminUser.getId(), this.adminPassword);
		}
	}

}
