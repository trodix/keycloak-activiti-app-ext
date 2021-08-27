package com.inteligr8.activiti;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.activiti.domain.idm.Tenant;
import com.activiti.service.idm.TenantService;
import com.activiti.service.license.LicenseService;

@Component
public class TenantFinderService {
	
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    
    @Autowired(required = false)
    private LicenseService licenseService;
    
    @Autowired(required = false)
    private TenantService tenantService;
    
    @Value("${keycloak-ext.tenant:#{null}}")
    private String tenant;
    
    public Long findTenantId() {
    	Tenant tenant = this.findTenant();
    	return tenant == null ? null : tenant.getId();
    }
    
    public Tenant findTenant() {
		this.logger.debug("Checking for a single tenant ...");
		
    	String tenantName = null;
    	if (this.tenant != null) {
    		tenantName = this.tenant;
    	} else {
    		List<Object[]> tenants = this.tenantService.getAllTenants();
    		if (tenants == null || tenants.isEmpty()) {
    			this.logger.warn("No tenants found!");
    			return null;
    		} else if (tenants.size() == 1) {
    			Object[] tenant = tenants.iterator().next();
    			this.logger.debug("Only one tenant available; selecting it: {}", tenant[0]);
    			return this.tenantService.getTenant((Long)tenant[0]);
    		} else {
    			tenantName = this.licenseService.getDefaultTenantName();
    		}
    	}
    	
		this.logger.debug("Trying to find by tenant name: {}", tenantName);
		
    	List<Tenant> tenants = this.tenantService.findTenantsByName(tenantName);
    	if (tenants == null || tenants.isEmpty()) {
    		this.logger.warn("Named tenant not found");
    		return null;
    	}

		this.logger.debug("Found {} tenants with name {}; selecting the first one", tenants.size(), tenantName);
    	return tenants.iterator().next();
    }
    
    public Collection<Tenant> getTenants() {
		List<Object[]> tenantObjs = this.tenantService.getAllTenants();
		
		List<Tenant> tenants = new ArrayList<>(tenantObjs.size());
		for (Object[] tenantObj : tenantObjs) {
			if (tenantObj != null && tenantObj[0] != null) {
				Tenant tenant = this.tenantService.getTenant((Long)tenantObj[0]);
				tenants.add(tenant);
			}
		}
		
		return tenants;
    }

}
