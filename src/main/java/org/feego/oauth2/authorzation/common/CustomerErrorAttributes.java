package org.feego.oauth2.authorzation.common;

import java.util.HashMap;
import java.util.Map;

import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.WebRequest;

/**
 * 用以替换spring boot原始错误返回的类
 * */

@Component
public class CustomerErrorAttributes extends DefaultErrorAttributes {
	@Override
	public Map<String,Object> getErrorAttributes(WebRequest webRequest, boolean includeStackTrace){
		Map<String,Object> err=super.getErrorAttributes(webRequest, includeStackTrace);
		Map<String,Object> data=new HashMap<>();
		data.put("error", err.get("error"));
		err.put("code", err.get("status"));
		err.put("data", data);
		return err;
	}
}
