package com.example.cryptography.Models;

import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public class SignupResponse {
    private String encryptedDek; //new
    private byte[] kekSalt;
    private String encryptedString;
    private byte[] kekIv;
    private byte[] dekIv;

}
