package com.example.cryptography.Models;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class LoginRequestInput {
    private String password;
    private String dataToDecrypt;
    private byte[] kekSalt;
    private byte[] kekIv;
    private byte[] dekIv;
    private String encryptedDek;

}
