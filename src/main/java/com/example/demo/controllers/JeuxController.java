package com.example.demo.controllers;

import java.text.ParseException;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

import org.springframework.data.domain.Page;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.example.demo.entities.Categorie;
import com.example.demo.entities.Jeux;
import com.example.demo.service.JeuxService;

import jakarta.validation.Valid;

@Controller
public class JeuxController {

	@Autowired
	JeuxService jeuxService;
	
	
	
	@GetMapping("/accessDenied")
	public String error()
	{
	return "accessDenied";
	}
	
	
	
	@RequestMapping("/ListeJeux")
	public String listeJeux(ModelMap modelMap , 
			@RequestParam (name="page",defaultValue = "0") int page,
			@RequestParam (name="size", defaultValue = "2") int size)
	{
		Page<Jeux> jeux = jeuxService.getAllJeuxParPage(page, size);
		modelMap.addAttribute("jeux", jeux);
		 modelMap.addAttribute("pages", new int[jeux.getTotalPages()]);
		modelMap.addAttribute("currentPage", page);
		return "listeJeux";
	}
	@RequestMapping("/showCreate")
	public String showCreate(ModelMap modelMap)
	{
		List<Categorie> cats = jeuxService.getAllCategories();

	modelMap.addAttribute("jeux", new Jeux());
	modelMap.addAttribute("mode", "new");
	modelMap.addAttribute("categories", cats);

	return "formJeux";
	}
	/*@RequestMapping("/saveJeux")
	public String saveJeux(@ModelAttribute("jeux") Jeux jeux,
	@RequestParam("date") String date,
	ModelMap modelMap) throws ParseException
	{
	//conversion de la date
	 SimpleDateFormat dateformat = new SimpleDateFormat("yyyy-MM-dd");
	 Date dateCreation = dateformat.parse(String.valueOf(date));
	 jeux.setDate(dateCreation);

	Jeux saveJeux = jeuxService.saveJeux(jeux);
	String msg ="jeux enregistré avec Id "+saveJeux.getId();
	modelMap.addAttribute("msg", msg);
	return "createJeux";
	}*/
	 
	@RequestMapping("/saveJeux")
	public String saveJeux(@Valid Jeux jeux,
	 BindingResult bindingResult 
	 ,@RequestParam (name="page",defaultValue = "0") int page,
	 @RequestParam (name="size", defaultValue = "2") int size)
	{
		int currentPage;
		boolean isNew = false;
		if (bindingResult.hasErrors()) return "formJeux";
		if (jeux.getId()==null) //ajout
		isNew=true;
		jeuxService.saveJeux(jeux);
		if (isNew) //ajout
		{
		Page<Jeux> jeuxx = jeuxService.getAllJeuxParPage(page, size);
		currentPage = jeuxx.getTotalPages()-1;
		}
		else //modif
		currentPage=page;
		return ("redirect:/ListeJeux?page="+currentPage+"&size="+size);
		}
	 
	 
	 
	@RequestMapping("/supprimerJeux")
	public String supprimerJeux(@RequestParam("id") Long id,
	 ModelMap modelMap ,
	 @RequestParam (name="page",defaultValue = "0") int page,
	 @RequestParam (name="size", defaultValue = "2") int size)
	{
		jeuxService.deleteJeuxById(id);
		Page<Jeux> jeux = jeuxService.getAllJeuxParPage(page,
				size);
				modelMap.addAttribute("jeux", jeux);
				modelMap.addAttribute("pages", new int[jeux.getTotalPages()]);
				modelMap.addAttribute("currentPage", page);
				modelMap.addAttribute("size", size);
				return "listeJeux";
	}

	 @RequestMapping("/modifierJeux")
	public String editerJeux(@RequestParam("id") Long id,
	 ModelMap modelMap,@RequestParam (name="page",defaultValue = "0") int page,
	 @RequestParam (name="size", defaultValue = "2") int size)
	{
	Jeux j= jeuxService.getJeux(id);
	List<Categorie> cats = jeuxService.getAllCategories();
	modelMap.addAttribute("jeux", j);
	modelMap.addAttribute("mode", "edit");
	modelMap.addAttribute("categories", cats);
	modelMap.addAttribute("page", page);
	modelMap.addAttribute("size", size);

	return "formJeux";
	}
	@RequestMapping("/updateJeux")
	public String updateProduit(@ModelAttribute("produit") Jeux
	jeux, @RequestParam("date") String date,
	 ModelMap modelMap) throws ParseException
	{
	//conversion de la date
	 SimpleDateFormat dateformat = new SimpleDateFormat("yyyy-MM-dd");
	 Date dateCreation = dateformat.parse(String.valueOf(date));
	 jeux.setDate(dateCreation);

	 jeuxService.updateJeux(jeux);
	 List<Jeux> prods = jeuxService.getAllJeux();
	 modelMap.addAttribute("jeux", prods);
	return "listeJeux";
	}

	
}
