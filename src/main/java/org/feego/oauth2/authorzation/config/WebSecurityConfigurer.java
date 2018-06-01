package org.feego.oauth2.authorzation.config;


import org.feego.oauth2.authorzation.common.RestAuthenticationEntryPoint;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigurer extends WebSecurityConfigurerAdapter {
	@Override
	public void configure(HttpSecurity http) throws Exception {
		http
        .authorizeRequests()
            .antMatchers("/oauth/token").permitAll()
            .antMatchers("/h2-console/**").permitAll()
            .anyRequest().hasRole("CLIENT")
            .and()
        .exceptionHandling()
            .authenticationEntryPoint(new RestAuthenticationEntryPoint()) //customer AuthenticationEntryPoint to response json string
            .and()
        // TODO: put CSRF protection back into this endpoint
        .csrf()
            .requireCsrfProtectionMatcher(new AntPathRequestMatcher("/oauth/authorize"))
            .disable()
        //以下仅为h2数据库的web console，生产环境中，应该去除
        .headers()
        	.frameOptions()
            .disable();
	}
}
