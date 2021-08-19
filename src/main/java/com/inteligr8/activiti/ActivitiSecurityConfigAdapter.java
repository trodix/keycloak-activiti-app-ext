package com.inteligr8.activiti;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * @author brian@inteligr8.com
 */
public interface ActivitiSecurityConfigAdapter extends Comparable<ActivitiSecurityConfigAdapter> {
	
	/**
	 * Is the adapter enabled?  This allows for configurable enablement.
	 * 
	 * @return true if enabled; false otherwise
	 */
	boolean isEnabled();
	
	/**
	 * The lower the value, the higher the priority.  The OOTB security
	 * configuration uses priority 0.  Use negative values to supersede it.
	 * Anything with equal priorities should be considered unordered and may
	 * execute in a random order.
	 * 
	 * @return A priority; may be negative or positive
	 */
	int getPriority();
	
	/**
	 * @see com.activiti.api.security.AlfrescoSecurityConfigOverride
	 */
	void configureGlobal(AuthenticationManagerBuilder authmanBuilder, UserDetailsService userDetailsService);
	
	@Override
	default int compareTo(ActivitiSecurityConfigAdapter adapter) {
		return Integer.compare(this.getPriority(), adapter.getPriority());
	}

}
