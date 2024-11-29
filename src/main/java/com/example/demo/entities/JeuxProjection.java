package com.example.demo.entities;

import org.springframework.data.rest.core.config.Projection;
@Projection(name = "nomJeux", types = { Jeux.class })
public interface JeuxProjection {
	
	
	
	public String getNom();
	

}
