package org.feego.oauth2.authorzation.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer server) throws Exception {
		// TODO Auto-generated method stub
		server
			.tokenKeyAccess("isAnonymous() || hasAuthority('ROLE_TRUSTED_CLIENT')")
			.checkTokenAccess("hasAuthority('ROLE_CLIENT')");
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer client) throws Exception {
		// TODO Auto-generated method stub
		client.jdbc(datasource)
			.withClient("testClientId")
			.resourceIds("testResourceId")
			.authorizedGrantTypes("authorization_code", "implicit","client_credentials")
			.authorities("TRUSTED_CLIENT")
			.scopes("read","write")
			.secret(passwordEncoder.encode("secret"))
			.accessTokenValiditySeconds(86400)
			.refreshTokenValiditySeconds(60);
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoint) throws Exception {
		// TODO Auto-generated method stub
		endpoint
			.tokenStore(jdbcTokenStore);
	}
	
	@Bean
	public JdbcTokenStore getTokenStore() {
		return new JdbcTokenStore(datasource);
	}
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
	    return new BCryptPasswordEncoder();
	}
}
