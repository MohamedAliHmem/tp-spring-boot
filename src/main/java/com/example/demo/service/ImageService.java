package com.example.demo.service;

import com.example.demo.entities.Image;
import org.springframework.http.ResponseEntity;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

public interface ImageService {
    Image uplaodImage(MultipartFile file) throws IOException;
    Image getImageDetails(Long id) throws IOException;
    ResponseEntity<byte[]> getImage(Long id) throws IOException;
    void deleteImage(Long id) ;
    Image uplaodImageJeu(MultipartFile file,Long idProd) throws IOException;
    List<Image> getImagesParJeu(Long prodId);
}
