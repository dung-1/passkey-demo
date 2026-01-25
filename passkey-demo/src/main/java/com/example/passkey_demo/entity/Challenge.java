package com.example.passkey_demo.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "challenges", 
       indexes = {
           @Index(name = "idx_email_type_created", columnList = "email,type,createdAt")
       })
@Data
@NoArgsConstructor
public class Challenge {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(columnDefinition = "VARBINARY(500)")
    private byte[] challenge;

    private String email;

    @Enumerated(EnumType.STRING)
    private ChallengeType type;

    private LocalDateTime createdAt;

    private LocalDateTime expiresAt;

    public enum ChallengeType {
        REGISTRATION,
        AUTHENTICATION
    }

    public Challenge(byte[] challenge, String email, ChallengeType type) {
        this.challenge = challenge;
        this.email = email;
        this.type = type;
        this.createdAt = LocalDateTime.now();
        this.expiresAt = LocalDateTime.now().plusMinutes(5); // Expire after 5 minutes
    }

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiresAt);
    }
}
