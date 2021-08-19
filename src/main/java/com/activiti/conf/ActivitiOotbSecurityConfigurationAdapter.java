package com.activiti.conf;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import com.inteligr8.activiti.ActivitiSecurityConfigAdapter;

/**
 * This class/bean executes the OOTB security configuration without the
 * override, so you can still use its OOTB features.  This will allow you to
 * enable/disable features, chain them, and uset he OOTB features as a
 * fallback or failsafe.
 * 
 * This class must be in the com.activiti.conf package so it can use protected
 * fields and methods of the OOTB class instance.
 * 
 * @author brian@inteligr8.com
 * @see com.activiti.conf.SecurityConfiguration
 */
@Component
public class ActivitiOotbSecurityConfigurationAdapter implements ActivitiSecurityConfigAdapter {
	
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    
    @Value("${keycloak-ext.ootbSecurityConfig.enabled:true}")
    private boolean enabled;
    
    @Autowired
    private SecurityConfiguration ootbSecurityConfig;
    
    @Override
    public boolean isEnabled() {
    	return this.enabled;
    }
    
    public int getPriority() {
    	return 0;
    }
	
	@Override
	public void configureGlobal(AuthenticationManagerBuilder authmanBuilder, UserDetailsService userDetailsService) {
		this.logger.trace("configureGlobal()");

		this.logger.info("Using OOTB authentication");
		
		// unset override (which has already been called in order to get here)
		this.ootbSecurityConfig.securityConfigOverride = null;
		
		this.ootbSecurityConfig.configureGlobal(authmanBuilder);
	}

}
