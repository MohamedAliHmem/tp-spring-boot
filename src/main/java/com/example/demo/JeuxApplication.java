package com.example.demo;





import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.rest.core.config.RepositoryRestConfiguration;

import com.example.demo.entities.Categorie;
import com.example.demo.entities.Jeux;
import com.example.demo.service.JeuxService;

@SpringBootApplication
public class JeuxApplication implements CommandLineRunner {

	@Autowired
	JeuxService jeuxService;
	@Autowired
	private RepositoryRestConfiguration repositoryRestConfiguration;
	
	public static void main(String[] args) {
		SpringApplication.run(JeuxApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		// TODO Auto-generated method stub
		repositoryRestConfiguration.exposeIdsFor(Jeux.class,Categorie.class);

		}
	}


