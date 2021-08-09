package com.inteligr8.activiti.ais;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AuthenticationProvider;

import com.activiti.api.security.AlfrescoAuthenticationProviderOverride;
import com.inteligr8.activiti.Authenticator;

/**
 * FIXME This would be nice, but with AIS enabled, it is never called.  The use
 * of this requires a fix from the Alfresco/Activiti team.  Their AIS
 * authentication logic appears to have been hastily added, breaking this
 * override possibility.  We are instead using the heavier weight
 * `OidcSecurityConfigurationAdapter` and re-implementing the authentication
 * logic discovered in the `activiti-app` project
 * `com.activiti.conf.SecurityConfiguration` class.
 * 
 * @author brian.long@yudrio.com
 * @see IdentityServiceSecurityConfigurationAdapter
 */
//@Component
public class IdentityServiceAuthenticationProviderAdapter implements AlfrescoAuthenticationProviderOverride {
	
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    
    @Autowired
    @Qualifier("activiti-app.authenticator")
    private Authenticator authenticator;
    
    @Override
    public AuthenticationProvider createAuthenticationProvider() {
    	this.logger.trace("createAuthenticationProvider()");
    	return new InterceptingIdentityServiceAuthenticationProvider(this.authenticator);
    }

}
