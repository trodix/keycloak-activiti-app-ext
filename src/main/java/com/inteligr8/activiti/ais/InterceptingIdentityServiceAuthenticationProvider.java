package com.inteligr8.activiti.ais;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import com.activiti.security.identity.service.authentication.provider.IdentityServiceAuthenticationProvider;
import com.inteligr8.activiti.Authenticator;

/**
 * This class/bean extends the APS AIS OOTB authentication provider.  It uses
 * an `Authenticator` to pre/post authenticate.  The pre-authentication allows
 * us to circumvent the problem with AIS and missing users.  The
 * post-authentication allow us to synchronize groups/authorities.
 * 
 * @author brian.long@yudrio.com
 */
public class InterceptingIdentityServiceAuthenticationProvider extends IdentityServiceAuthenticationProvider {
	
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private final Authenticator authenticator;
    
    public InterceptingIdentityServiceAuthenticationProvider(Authenticator authenticator) {
    	this.authenticator = authenticator;
	}
    
    @Override
    public Authentication authenticate(Authentication auth) throws AuthenticationException {
		this.logger.trace("authenticate({})", auth.getName());
		
		this.authenticator.preAuthenticate(auth);
    	this.logger.debug("Pre-authenticated user: {}", auth.getName());
    	
    	auth = super.authenticate(auth);
    	this.logger.debug("Authenticated user '{}' with authorities: {}", auth.getName(), auth.getAuthorities());
    	
    	// FIXME temporary for debugging
    	if (auth.getName().equals("admin@app.activiti.com"))
    		return auth;
    	
    	this.authenticator.postAuthenticate(auth);
    	this.logger.debug("Post-authenticated user: {}", auth.getName());
    	
    	return auth;
    }
    
}
