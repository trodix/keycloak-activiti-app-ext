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

import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import com.activiti.api.security.AlfrescoSecurityConfigOverride;

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
    private List<DataFixer> fixers;
	
	@Override
	public void configureGlobal(AuthenticationManagerBuilder authmanBuilder, UserDetailsService userDetailsService) {
		this.logger.trace("configureGlobal()");
		
		Collections.sort(this.adapters);
		
		if (this.fixers != null) {
			for (DataFixer fixer : this.fixers)
				fixer.fix();
		}
		
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

}
