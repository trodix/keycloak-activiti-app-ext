package com.inteligr8.activiti;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.activiti.domain.idm.User;
import com.activiti.service.api.UserService;

/**
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
