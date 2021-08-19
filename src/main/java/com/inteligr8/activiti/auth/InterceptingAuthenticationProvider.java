package com.inteligr8.activiti.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * This class/bean provides a pre/post authentication capability to the
 * Spring AuthenticationProvider.  The pre-authentication hook allows us to
 * circumvent the problem with authenticating missing users.  The
 * post-authentication hook allow us to synchronize groups/authorities.
 * 
 * @author brian@inteligr8.com
 */
public class InterceptingAuthenticationProvider implements AuthenticationProvider {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private final AuthenticationProvider provider;
    private final Authenticator authenticator;
    
    public InterceptingAuthenticationProvider(AuthenticationProvider provider, Authenticator authenticator) {
    	this.provider = provider;
    	this.authenticator = authenticator;
	}
    
    @Override
    public boolean supports(Class<?> authClass) {
    	return this.provider.supports(authClass);
    }
    
    @Override
    public Authentication authenticate(Authentication auth) throws AuthenticationException {
		this.logger.trace("authenticate({})", auth.getName());
		
		this.authenticator.preAuthenticate(auth);
    	this.logger.debug("Pre-authenticated user: {}", auth.getName());
    	
    	auth = this.provider.authenticate(auth);
    	this.logger.debug("Authenticated user '{}' with authorities: {}", auth.getName(), auth.getAuthorities());
    	
    	this.authenticator.postAuthenticate(auth);
    	this.logger.debug("Post-authenticated user: {}", auth.getName());
    	
    	return auth;
    }
    
}
