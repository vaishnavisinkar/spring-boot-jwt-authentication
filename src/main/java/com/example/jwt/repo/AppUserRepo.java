package com.example.jwt.repo;

import com.example.jwt.model.AppUser;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AppUserRepo extends MongoRepository<AppUser, String> {

    boolean existsByUsername(String username);

    Optional<AppUser> findByUsername(String username);
}
