package com.inteligr8.activiti.ais;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import com.activiti.api.msmt.MsmtTenantResolver;
import com.activiti.api.security.AlfrescoSecurityConfigOverride;
import com.activiti.conf.MsmtProperties;
import com.inteligr8.activiti.Authenticator;

/**
 * This class/bean overrides the AIS authentication provider, enabling a more
 * complete integration with AIS.
 * 
 * FIXME This is not optimal, but with AIS enabled, we cannot use the proper
 * override.
 * 
 * @author brian.long@yudrio.com
 * @see IdentityServiceAuthenticationProviderAdapter
 */
@Component
public class IdentityServiceSecurityConfigurationAdapter implements AlfrescoSecurityConfigOverride {
	
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    
    @Value("${keycloak.ext.odic.enabled:true}")
    private boolean enabled;

    @Autowired
    protected MsmtProperties msmtProperties;

    @Autowired(required = false) // Only when multi-schema multi-tenant is enabled
    protected MsmtTenantResolver tenantResolver;
    
    @Autowired
    @Qualifier("activiti-app.authenticator")
    private Authenticator authenticator;
    
    protected Authenticator getAuthenticator() {
		return this.authenticator;
	}
	
	@Override
	public void configureGlobal(AuthenticationManagerBuilder authmanBuilder, UserDetailsService userDetailsService) {
		this.logger.trace("configureGlobal()");
		
		if (this.enabled) {
			this.logger.info("Using Keycloak authentication extension, featuring creation of missing users and authority synchronization");
			
			InterceptingIdentityServiceAuthenticationProvider provider = new InterceptingIdentityServiceAuthenticationProvider(this.getAuthenticator());
			if (this.msmtProperties.isMultiSchemaMultiTenantEnabled())
				provider.setTenantResolver(this.tenantResolver);
			provider.setUserDetailsService(userDetailsService);
			provider.setGrantedAuthoritiesMapper(new SimpleAuthorityMapper());
			
			authmanBuilder.authenticationProvider(provider);
		}
	}

}
