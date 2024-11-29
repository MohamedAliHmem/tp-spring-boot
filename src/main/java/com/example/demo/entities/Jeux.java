package com.example.demo.entities;

import java.util.Date;


import org.springframework.format.annotation.DateTimeFormat;


import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Temporal;
import jakarta.persistence.TemporalType;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PastOrPresent;
import jakarta.validation.constraints.Size;
@Entity
public class Jeux {
	
	public Jeux(String nom, Double prix, Date date) {
		super();
		this.nom = nom;
		this.prix = prix;
		this.date = date;
	}

	public Jeux() {
		super();
		// TODO Auto-generated constructor stub
	}
	@Id 
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id ;
	@NotNull
	@Size (min = 4,max = 15)
	private String nom ; 
	
	@ManyToOne
	private Categorie categorie ;
	
	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getNom() {
		return nom;
	}

	public void setNom(String nom) {
		this.nom = nom;
	}

	public Double getPrix() {
		return prix;
	}

	public void setPrix(Double prix) {
		this.prix = prix;
	}

	public Date getDate() {
		return date;
	}

	public void setDate(Date date) {
		this.date = date;
	}
	@Min(value = 10)
	@Max(value = 10000)
	private Double prix ;
	@Temporal(TemporalType.DATE)
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	@PastOrPresent
	private Date date ;

	@Override
	public String toString() {
		return "Jeux [id=" + id + ", nom=" + nom + ", prix=" + prix + ", date=" + date + "]";
	}

	public Categorie getCategorie() {
		return categorie;
	}

	public void setCategorie(Categorie categorie) {
		this.categorie = categorie;
	}
	
	

}
