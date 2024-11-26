package com.example.demo.entities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;

@Entity
@Builder
@Data
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Image {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long idImage ;
    private String name ;
    private String type ;
    @Column( name = "IMAGE" , length = 4048576 )
    @Lob
    private byte[] image;
    @ManyToOne()
    @JoinColumn(name="JEUX_ID")
    @JsonIgnore
    private Jeux jeux;



}
