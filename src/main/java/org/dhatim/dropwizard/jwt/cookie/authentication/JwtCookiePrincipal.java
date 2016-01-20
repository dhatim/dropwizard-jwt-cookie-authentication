/*
 * Copyright 2016 Dhatim.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.dhatim.dropwizard.jwt.cookie.authentication;

import java.security.Principal;

/**
 * A principal persisted in JWT cookies
 */
public interface JwtCookiePrincipal extends Principal{
    
    /**
     * Indicates if the cookie will be persistent (aka 'remember me')
     * @return if the cookie must be persistent
     */
   boolean isPersistent(); 
   
   /**
    * Indicates if this principal has the given role
    * @param role the role
    * @return true if the principal is in the given role, false otherwise
    */
   boolean hasRole(String role);
   
}
