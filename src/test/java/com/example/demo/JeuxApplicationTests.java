package com.example.demo;

import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;

import com.example.demo.entities.Categorie;
import com.example.demo.entities.Jeux;
import com.example.demo.repo.CategorieRepository;
import com.example.demo.repo.JeuxRepository;
import com.example.demo.service.JeuxService;

@SpringBootTest
class JeuxApplicationTests {

	@Autowired
	private JeuxRepository jeuxRepository;
	@Autowired
	private CategorieRepository categorieRepository ; 
	@Autowired
	private JeuxService jeuxService;
	@Test
	public void testCreateJeux() {
	Jeux prod = new Jeux("Fortnite ",999.99,new Date());
	jeuxRepository.save(prod);
	}
	
	/*@Test
	public void testCreateCategorie() {
	Categorie cat = new Categorie("Action","bla");
	categorieRepository.save(cat);
	}*/
	
	@Test
	public void testFindProduit()
	{
	Jeux j = jeuxRepository.findById(1L).get();
	System.out.println(j);
	}
	
	
	@Test
	public void testUpdateProduit()
	{
		Jeux j = jeuxRepository.findById(1L).get();
	j.setPrix(1000.0);
	jeuxRepository.save(j);
	}
	
	
	@Test
	public void testDeleteProduit()
	{
		jeuxRepository.deleteById(1L);;
	}

	
	@Test
	public void testListerTousProduits()
	{
	List<Jeux> jeux = jeuxRepository.findAll();
	for (Jeux j : jeux)
	{
	System.out.println(j);
	}
	}
	
	@Test
	public void testFindByNomJeuxContains()
	{
	Page<Jeux> jeux = jeuxService.getAllJeuxParPage(0,2);
	System.out.println(jeux.getSize());
	System.out.println(jeux.getTotalElements());
	System.out.println(jeux.getTotalPages());
	jeux.getContent().forEach(j -> {System.out.println(j.toString());
	 });
	/*ou bien
	for (Produit p : prods)
	{
	System.out.println(p);
	} */
	}
	@Test
	public void testFindJeuxByNom()
	{
	List<Jeux> jeux = jeuxRepository.findByNom("Valorant");
	for (Jeux j : jeux)
	{
	System.out.println(j);
	}
	}
	@Test
	public void testFindJeuxByNomContains()
	{
	List<Jeux> jeux = jeuxRepository.findByNomContains("Val");
	for (Jeux j : jeux)
	{
	System.out.println(j);
	}
	}
	
	@Test
	public void testfindByNomPrix()
	{
	List<Jeux> jeux = jeuxRepository.findByNomPrix("Valorant", 999.99);
	for (Jeux j : jeux)
	{
	System.out.println(j);
	}
	}
	
	@Test
	public void testfindByCategorie()
	{
	Categorie cat = new Categorie();
	cat.setId(1L);
	List<Jeux> jeux = jeuxRepository.findByCategorie(cat);
	for (Jeux j : jeux)
	{
	System.out.println(j);
	}
	}
	@Test
	public void findByCategorieId()
	{
	List<Jeux> jeux = jeuxRepository.findByCategorieId(1L);
	for (Jeux j : jeux)
	{
	System.out.println(j);
	}
	 }
	
	@Test
	public void testfindByOrderByNomJeuxAsc()
	{
	List<Jeux> jeux =
			jeuxRepository.findByOrderByNomAsc();
	for (Jeux j : jeux)
	{
	System.out.println(j);
	}
	}
	
	@Test
	public void testTrierProduitsNomsPrix()
	{
	List<Jeux> jeux = jeuxRepository.trierJeuxNomsPrix();
	for (Jeux j : jeux)
	{
	System.out.println(j);
	}
	}


}
