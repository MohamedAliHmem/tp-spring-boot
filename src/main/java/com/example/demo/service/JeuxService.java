package com.example.demo.service;

import java.util.List;

import org.springframework.data.domain.Page;

import com.example.demo.entities.Categorie;
import com.example.demo.entities.Jeux;

public interface JeuxService {
	Jeux saveJeux(Jeux j);
	Jeux updateJeux(Jeux j);
	void deleteJeux(Jeux j);
	void deleteJeuxById(Long id);
	Jeux getJeux(Long id);
	List<Jeux> getAllJeux();
	
	Page<Jeux> getAllJeuxParPage(int page, int size);
	
	
	List<Jeux> findByNomJeux(String nom);
	List<Jeux> findByNomJeuxContains(String nom);
	List<Jeux> findByNomPrix (String nom, Double prix);
	List<Jeux> findByCategorie (Categorie categorie);
	List<Jeux> findByCategorieId(Long id);
	List<Jeux> findByOrderByNomAsc();
	List<Jeux> trierJeuxsNomsPrix();
	
	
	List<Categorie> getAllCategories();


	
}
