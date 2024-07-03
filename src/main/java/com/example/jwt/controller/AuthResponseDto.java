package com.example.jwt.controller;

public record AuthResponseDto(String token, AuthStatus authStatus) {

}
