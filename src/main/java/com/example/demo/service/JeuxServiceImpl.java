package com.example.demo.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import com.example.demo.entities.Categorie;
import com.example.demo.entities.Jeux;
import com.example.demo.repo.CategorieRepository;
import com.example.demo.repo.JeuxRepository;
@Service
public class JeuxServiceImpl implements JeuxService {
	@Autowired
	CategorieRepository categorieRepository;

	@Autowired
	private JeuxRepository jeuxRepository ;

	@Override
	public Jeux saveJeux(Jeux j) {
		// TODO Auto-generated method stub
		return jeuxRepository.save(j);
	}

	@Override
	public Jeux updateJeux(Jeux j) {
		// TODO Auto-generated method stub
		return jeuxRepository.save(j);
	}

	@Override
	public void deleteJeux(Jeux j) {
		// TODO Auto-generated method stub
		jeuxRepository.delete(j);
	}

	@Override
	public void deleteJeuxById(Long id) {
		// TODO Auto-generated method stub
		jeuxRepository.deleteById(id);
	}

	@Override
	public Jeux getJeux(Long id) {
		// TODO Auto-generated method stub
		return jeuxRepository.findById(id).get();
	}

	@Override
	public List<Jeux> getAllJeux() {
		// TODO Auto-generated method stub
		return jeuxRepository.findAll();
	}

	@Override
	public Page<Jeux> getAllJeuxParPage(int page, int size) {
		// TODO Auto-generated method stub
		return jeuxRepository.findAll(PageRequest.of(page, size));
	}

	@Override
	public List<Jeux> findByNomJeux(String nom) {
		// TODO Auto-generated method stub
		return jeuxRepository.findByNom(nom);
	}

	@Override
	public List<Jeux> findByNomJeuxContains(String nom) {
		// TODO Auto-generated method stub
		return jeuxRepository.findByNomContains(nom);
	}

	@Override
	public List<Jeux> findByNomPrix(String nom, Double prix) {
		// TODO Auto-generated method stub
		return jeuxRepository.findByNomPrix(nom, prix);
	}

	@Override
	public List<Jeux> findByCategorie(Categorie categorie) {
		// TODO Auto-generated method stub
		return jeuxRepository.findByCategorie(categorie);
	}

	@Override
	public List<Jeux> findByCategorieId(Long id) {
		// TODO Auto-generated method stub
		return jeuxRepository.findByCategorieId(id);
	}

	@Override
	public List<Jeux> findByOrderByNomAsc() {
		// TODO Auto-generated method stub
		return jeuxRepository.findByOrderByNomAsc();
	}

	@Override
	public List<Jeux> trierJeuxsNomsPrix() {
		// TODO Auto-generated method stub
		return jeuxRepository.trierJeuxNomsPrix();
	}

	@Override
	public List<Categorie> getAllCategories() {
		// TODO Auto-generated method stub
		return  categorieRepository.findAll();

	}

}
