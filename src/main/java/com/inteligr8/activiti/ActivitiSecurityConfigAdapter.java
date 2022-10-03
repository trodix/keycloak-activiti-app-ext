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

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * This provides a means to supporting multiple `SecurityConfigAdapter` options
 * in one code base, while allowing only the first enabled one to be used.
 * 
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
