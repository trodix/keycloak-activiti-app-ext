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
package com.inteligr8.activiti.keycloak;

import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import com.inteligr8.activiti.ActivitiSecurityConfigAdapter;
import com.inteligr8.activiti.auth.Authenticator;
import com.inteligr8.activiti.auth.InterceptingAuthenticationProvider;

/**
 * This class/bean injects a custom keycloak authentication provider into the
 * security configuration.
 * 
 * @author brian@inteligr8.com
 * @see org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider
 */
@Component
public class KeycloakSecurityConfigurationAdapter implements ActivitiSecurityConfigAdapter {
	
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    
    @Value("${keycloak-ext.keycloak.enabled:false}")
    private boolean enabled;

	// this assures execution before the OOTB impl (-10 < 0)
    @Value("${keycloak-ext.keycloak.priority:-5}")
    private int priority;
    
    @Autowired
    @Qualifier("keycloak-ext.activiti-app.authenticator")
    private Authenticator authenticator;
    
    protected Authenticator getAuthenticator() {
		return this.authenticator;
	}
    
    @Override
    public boolean isEnabled() {
    	return this.enabled;
    }
    
    @Override
    public int getPriority() {
    	return this.priority;
    }
	
	@Override
	public void configureGlobal(AuthenticationManagerBuilder auth, UserDetailsService userDetailsService) {
		this.logger.trace("configureGlobal()");
		
		this.logger.info("Using Keycloak authentication extension, featuring creation of missing users and authority synchronization");
		
		KeycloakAuthenticationProvider provider = new KeycloakAuthenticationProvider();
		provider.setGrantedAuthoritiesMapper(new SimpleAuthorityMapper());

		auth.authenticationProvider(new InterceptingAuthenticationProvider(provider, this.getAuthenticator()));
	}

}
