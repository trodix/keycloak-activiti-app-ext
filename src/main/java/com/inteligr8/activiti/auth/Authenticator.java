package com.inteligr8.activiti.auth;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public interface Authenticator {
	
    default void preAuthenticate(Authentication authentication) throws AuthenticationException {
    }
    
    default void postAuthenticate(Authentication authentication) throws AuthenticationException {
    }
    
}
