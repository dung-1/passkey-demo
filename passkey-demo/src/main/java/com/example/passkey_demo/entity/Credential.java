package com.example.passkey_demo.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "credentials")
@Data
@NoArgsConstructor
public class Credential {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(columnDefinition = "VARBINARY(500)")
    private byte[] credentialId;

    @Column(columnDefinition = "LONGBLOB")
    private byte[] publicKey;

    private Long signatureCount;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;
}