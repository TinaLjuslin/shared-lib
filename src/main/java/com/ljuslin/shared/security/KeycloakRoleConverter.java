package com.ljuslin.shared.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Denna klass extraherar roller från en Keycloak JWT-token och konverterar dem
 * till Spring Security-vänliga GrantedAuthorities.
 */
public class KeycloakRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        // Keycloak lagrar oftast roller i "realm_access" -> "roles"
        Map<String, Object> realmAccess = (Map<String, Object>) jwt.getClaims().get("realm_access");

        // Om inga roller finns, returnera en tom lista
        if (realmAccess == null || realmAccess.isEmpty() || !realmAccess.containsKey("roles")) {
            return Collections.emptyList();
        }

        // Hämta listan med rollnamn och mappa dem till SimpleGrantedAuthority
        // Vi lägger till prefixet "ROLE_" för att Spring Boot ska känna igen dem som roller
        return ((List<String>) realmAccess.get("roles")).stream()
                .map(roleName -> "ROLE_" + roleName)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
}