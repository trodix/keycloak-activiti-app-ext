package com.inteligr8.activiti.ais;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map.Entry;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessToken.Access;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import com.inteligr8.activiti.Authenticator;

public abstract class AbstractIdentityServiceActivitiAuthenticator implements Authenticator {
	
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    

    
    protected Set<String> getRoles(Authentication auth) {
    	Set<String> authorities = this.toSet(auth.getAuthorities());
		this.logger.debug("Auto-parsed authorities: {}", authorities);
		
		if (authorities.isEmpty()) {
			AccessToken atoken = this.getKeycloakAccessToken(auth);
			if (atoken == null) {
				this.logger.debug("Access token not available");
				return null;
			} else if (atoken.getRealmAccess() == null && atoken.getResourceAccess().isEmpty()) {
				this.logger.debug("Access token has no role information");
				return null;
			} else {
				if (atoken.getRealmAccess() != null) {
					this.logger.debug("Access token realm roles: {}", atoken.getRealmAccess().getRoles());
					authorities.addAll(atoken.getRealmAccess().getRoles());
				}
				
				for (Entry<String, Access> resourceAccess : atoken.getResourceAccess().entrySet()) {
					this.logger.debug("Access token resources '{}' roles: {}", resourceAccess.getKey(), resourceAccess.getValue().getRoles());
					authorities.addAll(resourceAccess.getValue().getRoles());
				}
	
				this.logger.debug("Access token authorities: {}", authorities);
			}
		}
		
		return authorities;
    }
    
    protected AccessToken getKeycloakAccessToken(Authentication auth) {
    	KeycloakSecurityContext ksc = this.getKeycloakSecurityContext(auth);
    	return ksc == null ? null : ksc.getToken();
    }
    
    @SuppressWarnings("unchecked")
	protected KeycloakSecurityContext getKeycloakSecurityContext(Authentication auth) {
		if (auth.getCredentials() instanceof KeycloakSecurityContext) {
			this.logger.debug("Found keycloak context in credentials");
			return (KeycloakSecurityContext)auth.getCredentials();
		} else if (auth.getPrincipal() instanceof KeycloakPrincipal) {
			this.logger.debug("Found keycloak context in principal: {}", auth.getPrincipal());
			return ((KeycloakPrincipal<? extends KeycloakSecurityContext>)auth.getPrincipal()).getKeycloakSecurityContext();
		} else if (!(auth instanceof KeycloakAuthenticationToken)) {
			this.logger.warn("Unexpected token: {}", auth.getClass());
    		return null;
    	}
    	
		KeycloakAuthenticationToken ktoken = (KeycloakAuthenticationToken)auth;
		if (ktoken.getAccount() != null) {
			this.logger.debug("Found keycloak context in account: {}", ktoken.getAccount().getPrincipal() == null ? null : ktoken.getAccount().getPrincipal().getName());
			return ktoken.getAccount().getKeycloakSecurityContext();
		} else {
			this.logger.warn("Unable to find keycloak security context");
			this.logger.debug("Principal: {}", auth.getPrincipal());
			this.logger.debug("Account: {}", ktoken.getAccount());
			if (auth.getPrincipal() != null)
				this.logger.debug("Principal type: {}", auth.getPrincipal().getClass());
			return null;
		}
    }
    
    protected Set<String> toSet(Collection<? extends GrantedAuthority> grantedAuthorities) {
    	Set<String> authorities = new HashSet<>(Math.max(grantedAuthorities.size(), 16));
    	for (GrantedAuthority grantedAuthority : grantedAuthorities) {
    		String authority = StringUtils.trimToNull(grantedAuthority.getAuthority());
    		if (authority == null)
    			this.logger.warn("The granted authorities include an empty authority!?: '{}'", grantedAuthority.getAuthority());
    		authorities.add(authority);
    	}
    	return authorities;
    }
}
