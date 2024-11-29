package com.example.demo.security;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import jakarta.servlet.http.HttpServletRequest;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter=
			new JwtGrantedAuthoritiesConverter();

	public AbstractAuthenticationToken convert(Jwt jwt) {
		Map<String, Object> realmAccess = (Map<String, Object>)
				jwt.getClaims().get("realm_access");
		if (realmAccess == null || realmAccess.isEmpty()) {
			return null;
		}
		Collection<GrantedAuthority> authorities = ((List<String>)
				realmAccess.get("roles"))
				.stream()
				.map(role -> new SimpleGrantedAuthority(role))
				.collect(Collectors.toList());

		//ajouter les rôles de la rubrique scope (email, profile)
		authorities = Stream.concat(
				jwtGrantedAuthoritiesConverter.convert(jwt).stream(),
				authorities.stream()
		).collect(Collectors.toSet());

		return new JwtAuthenticationToken(jwt,
				authorities,jwt.getClaim("preferred_username"));
	}
	@Autowired
	KeycloakRoleConverter keycloakRoleConverter;


	@Bean
	public SecurityFilterChain filterChain (HttpSecurity http) throws Exception
	{ http.sessionManagement( session ->
	session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
	.csrf( csrf -> csrf.disable())
	
	.cors(cors -> cors.configurationSource(new CorsConfigurationSource()
	{
	 @Override
	 public CorsConfiguration getCorsConfiguration(HttpServletRequest
	request) {
	 CorsConfiguration cors = new CorsConfiguration();

	cors.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
	cors.setAllowedMethods(Collections.singletonList("*"));
	cors.setAllowedHeaders(Collections.singletonList("*"));
	cors.setExposedHeaders(Collections.singletonList("Authorization"));
	 return cors;
	 }
	 }))
	
	 .authorizeHttpRequests( requests -> requests

	.requestMatchers("/api/all/**").hasAnyAuthority("ADMIN","USER")
	.requestMatchers(HttpMethod.GET,"/api/getbyid/**").hasAnyAuthority("ADMIN","USER")
	.requestMatchers(HttpMethod.POST,"/api/add-jeux/**").hasAnyAuthority("ADMIN")
	.requestMatchers(HttpMethod.PUT,"/api/updatejeux/**").hasAuthority("ADMIN")
	.requestMatchers(HttpMethod.DELETE,"/api/deljeux/**").hasAuthority("ADMIN")
	
	.anyRequest().authenticated() )
			.oauth2ResourceServer(ors->ors.jwt(jwt->
					jwt.jwtAuthenticationConverter(keycloakRoleConverter)));

	return http.build();
	}

}
