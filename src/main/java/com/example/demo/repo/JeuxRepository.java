package com.example.demo.repo;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

import com.example.demo.entities.Categorie;
import com.example.demo.entities.Jeux;
@RepositoryRestResource(path = "rest")

public interface JeuxRepository extends JpaRepository<Jeux, Long> {
	
	List<Jeux> findByNom(String nom);
	
	
	List<Jeux> findByNomContains(String nom);
	
	@Query("select j from Jeux j where j.nom like %?1 and j.prix > ?2")
	List<Jeux> findByNomPrix (String nom, Double prix);
	
	@Query("select j from Jeux j where j.categorie = ?1")
	List<Jeux> findByCategorie (Categorie categorie);
	
	List<Jeux> findByCategorieId(Long id);
	
	List<Jeux> findByOrderByNomAsc();
	
	@Query("select j from Jeux j order by j.nom ASC, j.prix DESC")
	List<Jeux> trierJeuxNomsPrix ();


}
