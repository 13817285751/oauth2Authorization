package org.feego.oauth2.authorzation.config;

import java.security.SecureRandom;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;

@EnableAuthorizationServer
@Configuration
public class AuthorizationServerConfigure implements AuthorizationServerConfigurer {
	@Autowired
	private DataSource datasource;
	
	@Autowired
	private JdbcTokenStore jdbcTokenStore;
	
	@Autowired
	private BCryptPasswordEncoder passwordEncoder;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer server) throws Exception {
		// TODO Auto-generated method stub
		server
			.tokenKeyAccess("isAnonymous() || hasAuthority('TRUSTED_CLIENT')")
			.checkTokenAccess("hasAuthority('TRUSTED_CLIENT')"); //需要和clientdetails中的authorities相一致
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer client) throws Exception {
		// TODO Auto-generated method stub
		client.jdbc(datasource)
			.withClient("testClientId")
				.resourceIds("testResourceId")
				.authorizedGrantTypes("authorization_code", "password","client_credentials","refresh_token")
				.authorities("TRUSTED_CLIENT")
				.scopes("read","write")
				.secret(passwordEncoder.encode("secret"))
				.accessTokenValiditySeconds(15)
				.refreshTokenValiditySeconds(30)
			.and().withClient("testResource")
				.resourceIds("myresource")
				.authorizedGrantTypes("client_credentials")
				.authorities("TRUSTED_CLIENT")
				.scopes("read")
				.secret(passwordEncoder.encode("secret"))
				.accessTokenValiditySeconds(15)
				.refreshTokenValiditySeconds(30);
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoint) throws Exception {
		// TODO Auto-generated method stub
		endpoint
			.tokenStore(jdbcTokenStore)
			.userDetailsService(userDetailsService)	//grant_type为password时，需要设置，如果为client_credentials，则可免去
			.authenticationManager(authenticationManager); //grant_type为password时，需要设置，如果为client_credentials，则可免去
	}
	
	@Bean
	public JdbcTokenStore getTokenStore() {
		return new JdbcTokenStore(datasource);
	}
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		SecureRandom random=new SecureRandom ("abc".getBytes());
		return new BCryptPasswordEncoder(5,random);
	}
}
