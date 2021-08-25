package com.inteligr8.activiti.keycloak;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessToken.Access;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.util.Pair;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import com.inteligr8.activiti.auth.Authenticator;

public abstract class AbstractKeycloakActivitiAuthenticator implements Authenticator, InitializingBean {
	
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    
    @Value("${keycloak-ext.createMissingUser:true}")
    protected boolean createMissingUser;

    @Value("${keycloak-ext.clearNewUserDefaultGroups:true}")
    protected boolean clearNewUserDefaultGroups;

    @Value("${keycloak-ext.createMissingGroup:true}")
    protected boolean createMissingGroup;

    @Value("${keycloak-ext.syncGroupAdd:true}")
    protected boolean syncGroupAdd;

    @Value("${keycloak-ext.syncGroupRemove:true}")
    protected boolean syncGroupRemove;

    @Value("${keycloak-ext.syncInternalGroups:false}")
    protected boolean syncInternalGroups;
    
    @Value("${keycloak-ext.resource.include.regex.patterns:#{null}}")
    protected String resourceRegexIncludes;
    
    @Value("${keycloak-ext.group.format.regex.patterns:#{null}}")
    protected String regexPatterns;
    
    @Value("${keycloak-ext.group.format.regex.replacements:#{null}}")
    protected String regexReplacements;
    
    @Value("${keycloak-ext.group.include.regex.patterns:#{null}}")
    protected String regexIncludes;
    
    @Value("${keycloak-ext.group.exclude.regex.patterns:#{null}}")
    protected String regexExcludes;
    
    protected final List<Pair<Pattern, String>> groupFormatters = new LinkedList<>();
    protected final Set<Pattern> resourceIncludes = new HashSet<>();
    protected final Set<Pattern> groupIncludes = new HashSet<>();
    protected final Set<Pattern> groupExcludes = new HashSet<>();
    
    @Override
    public void afterPropertiesSet() {
    	if (this.regexPatterns != null) {
    		String[] regexPatternStrs = StringUtils.split(this.regexPatterns, ',');
    		String[] regexReplaceStrs = this.regexReplacements == null ? new String[0] : StringUtils.split(this.regexReplacements, ",");
    		for (int i = 0; i < regexPatternStrs.length; i++) {
    			Pattern regexPattern = Pattern.compile(regexPatternStrs[i]);
    			String regexReplace = (i < regexReplaceStrs.length) ? regexReplaceStrs[i] : "";
    	    	this.groupFormatters.add(Pair.of(regexPattern, regexReplace));
    		}
    	}
    	
    	if (this.resourceRegexIncludes != null) {
    		String[] regexPatternStrs = StringUtils.split(this.resourceRegexIncludes, ',');
    		for (int i = 0; i < regexPatternStrs.length; i++)
    			this.resourceIncludes.add(Pattern.compile(regexPatternStrs[i]));
    	}
    	
    	if (this.regexIncludes != null) {
    		String[] regexPatternStrs = StringUtils.split(this.regexIncludes, ',');
    		for (int i = 0; i < regexPatternStrs.length; i++)
    			this.groupIncludes.add(Pattern.compile(regexPatternStrs[i]));
    	}
    	
    	if (this.regexExcludes != null) {
    		String[] regexPatternStrs = StringUtils.split(this.regexExcludes, ',');
    		for (int i = 0; i < regexPatternStrs.length; i++)
    			this.groupExcludes.add(Pattern.compile(regexPatternStrs[i]));
    	}
    }
    

    
    protected Map<String, String> getKeycloakRoles(Authentication auth) {
    	Map<String, String> authorities = new HashMap<>();
		
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
				Collection<String> roles = this.filterRoles(atoken.getRealmAccess().getRoles());
				Map<String, String> mappedRoles = this.formatRoles(roles);
				authorities.putAll(mappedRoles);
			}
			
			for (Entry<String, Access> resourceAccess : atoken.getResourceAccess().entrySet()) {
				if (this.includeResource(resourceAccess.getKey())) {
					this.logger.debug("Access token resources '{}' roles: {}", resourceAccess.getKey(), resourceAccess.getValue().getRoles());
					Collection<String> roles = this.filterRoles(resourceAccess.getValue().getRoles());
					Map<String, String> mappedRoles = this.formatRoles(roles);
					authorities.putAll(mappedRoles);
				}
			}

			this.logger.debug("Access token authorities: {}", authorities);
		}
		
		return authorities;
    }
    
    private Collection<String> filterRoles(Collection<String> unfilteredRoles) {
		if (this.groupIncludes.isEmpty() && this.groupExcludes.isEmpty())
			return unfilteredRoles;
		
    	Set<String> filteredRoles = new HashSet<>(unfilteredRoles.size());
    	
    	for (String role : unfilteredRoles) {
    		boolean doInclude = this.groupIncludes.isEmpty();
    		for (Pattern regex : this.groupIncludes) {
    			Matcher matcher = regex.matcher(role);
    			if (matcher.matches()) {
    				this.logger.debug("Role matched inclusion filter: {}", role);
    				doInclude = true;
    				break;
    			}
    		}
    		
    		if (doInclude) {
    			for (Pattern regex : this.groupExcludes) {
        			Matcher matcher = regex.matcher(role);
        			if (matcher.matches()) {
        				this.logger.debug("Role matched exclusion filter: {}", role);
        				doInclude = false;
        				break;
        			}
        		}
    			
    			if (doInclude)
    				filteredRoles.add(role);
    		}
    	}
    	
    	return filteredRoles;
    }
    
    private Map<String, String> formatRoles(Collection<String> unformattedRoles) {
    	Map<String, String> formattedRoles = new HashMap<>(unformattedRoles.size());
    	
    	for (String unformattedRole : unformattedRoles) {
    		String formattedRole = null;
    		
    		for (Pair<Pattern, String> regex : this.groupFormatters) {
    			Matcher matcher = regex.getFirst().matcher(unformattedRole);
    			if (matcher.matches()) {
    				this.logger.trace("Role matched formatter: {}", unformattedRole);
    				formattedRole = matcher.replaceFirst(regex.getSecond());
    				this.logger.debug("Role formatted: {}", formattedRole);
    				break;
    			}
    		}
    		
    		formattedRoles.put(unformattedRole, formattedRole == null ? unformattedRole : formattedRole);
    	}
    	
    	return formattedRoles;
    }
    
    private boolean includeResource(String resource) {
		if (this.resourceIncludes.isEmpty())
			return true;
		
		for (Pattern resourceInclude : this.resourceIncludes) {
			Matcher matcher = resourceInclude.matcher(resource);
			if (matcher.matches())
				return true;
		}
		
		return false;
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
    
    protected <K, V> boolean removeMapEntriesByValue(Map<K, V> map, V value) {
    	if (value == null)
    		throw new IllegalArgumentException();
    	
    	int found = 0;
    	
    	Iterator<Entry<K, V>> i = map.entrySet().iterator();
    	while (i.hasNext()) {
    		Entry<K, V> entry = i.next();
    		if (entry.getValue() != null && value.equals(entry.getValue())) {
    			i.remove();
    			found++;
    		}
    	}
    	
    	return found > 0;
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
