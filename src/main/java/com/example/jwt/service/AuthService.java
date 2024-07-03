package com.example.jwt.service;

import org.springframework.stereotype.Service;

public interface AuthService {
    String login(String username, String password);

    String signUp(String name, String username, String password);
}
