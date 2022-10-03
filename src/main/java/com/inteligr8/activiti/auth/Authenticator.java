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
package com.inteligr8.activiti.auth;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public interface Authenticator {
	
    default void preAuthenticate(Authentication authentication) throws AuthenticationException {
    }
    
    default void postAuthenticate(Authentication authentication) throws AuthenticationException {
    }
    
}
