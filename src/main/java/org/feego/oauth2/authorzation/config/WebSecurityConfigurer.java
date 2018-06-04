package org.feego.oauth2.authorzation.config;


import javax.sql.DataSource;

import org.feego.oauth2.authorzation.common.RestAuthenticationEntryPoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigurer extends WebSecurityConfigurerAdapter {
	@Autowired
	private DataSource dataSource;
	
	@Autowired
	private BCryptPasswordEncoder passwordEncoder;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
        .authorizeRequests()
            .antMatchers("/oauth/token").permitAll()
            .antMatchers("/h2-console/**").permitAll()
            .anyRequest().hasRole("CLIENT")
            .and()
        //.exceptionHandling()
            //.authenticationEntryPoint(new RestAuthenticationEntryPoint()) //customer AuthenticationEntryPoint to response json string
            //.and()
        // TODO: put CSRF protection back into this endpoint
        .csrf()
            .requireCsrfProtectionMatcher(new AntPathRequestMatcher("/oauth/authorize"))
            .disable()
        //以下仅为h2数据库的web console，生产环境中，应该去除
        .headers()
        	.frameOptions()
            .disable();
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.jdbcAuthentication().dataSource(dataSource)
			.withUser("jack").password(passwordEncoder.encode("123")).roles("USER").and()
			.withUser("mary").password(passwordEncoder.encode("123")).roles("USER");
	}
	
	@Bean
	public AuthenticationManager getauthenticationManager() throws Exception {
		return super.authenticationManagerBean();
	}
	
	@Bean
	public UserDetailsService getUserDetailsService() throws Exception {
		return super.userDetailsServiceBean();
	}
	
}
