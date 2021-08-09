package com.inteligr8.activiti.ais;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.OidcKeycloakAccount;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.representations.AccessToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import com.activiti.security.identity.service.authentication.provider.IdentityServiceAuthenticationToken;
import com.inteligr8.activiti.Authenticator;

public abstract class AbstractIdentityServiceActivitiAuthenticator implements Authenticator {
	
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    

    
    protected AccessToken getOidcAccessToken(Authentication auth) {
    	KeycloakSecurityContext ksc = this.getKeycloakSecurityContext(auth);
    	return ksc.getToken();
    }
    
    @SuppressWarnings("unchecked")
	protected KeycloakSecurityContext getKeycloakSecurityContext(Authentication auth) {
    	if (auth instanceof KeycloakAuthenticationToken) {
    		this.logger.debug("Fetching KeycloakSecurityContext from KeycloakAuthenticationToken");
    		if (auth.getPrincipal() instanceof KeycloakPrincipal) {
    			return ((KeycloakPrincipal<? extends KeycloakSecurityContext>)auth.getPrincipal()).getKeycloakSecurityContext();
    		} else {
    			return null;
    		}
    	} else if (auth instanceof IdentityServiceAuthenticationToken) {
    		this.logger.debug("Fetching KeycloakSecurityContext from IdentityServiceAuthenticationToken");
    		OidcKeycloakAccount account = ((IdentityServiceAuthenticationToken)auth).getAccount();
    		return account == null ? null : account.getKeycloakSecurityContext();
    	} else {
    		return null;
    	}
    }
    
    protected Set<String> toSet(Collection<? extends GrantedAuthority> grantedAuthorities) {
    	Set<String> authorities = new HashSet<>(grantedAuthorities.size());
    	for (GrantedAuthority grantedAuthority : grantedAuthorities)
    		authorities.add(grantedAuthority.getAuthority());
    	return authorities;
    }
}
