package com.example.passkey_demo.repository;

import java.time.LocalDateTime;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.example.passkey_demo.entity.Challenge;
import com.example.passkey_demo.entity.Challenge.ChallengeType;

@Repository
public interface ChallengeRepository extends JpaRepository<Challenge, Long> {

    Optional<Challenge> findByEmailAndType(String email, Challenge.ChallengeType type);

    /**
     * Get the latest challenge (by createdAt DESC) for email and type. Ensure
     * we get the challenge that was created most recently.
     */
    Optional<Challenge> findFirstByEmailAndTypeOrderByCreatedAtDesc(
            String email, Challenge.ChallengeType type);

    /**
     * Delete all challenges of a user by email and type. Used for cleanup
     * before creating a new challenge.
     */
    @Modifying
    void deleteAllByEmailAndType(String email, ChallengeType type);

    @Modifying
    @Query("DELETE FROM Challenge c WHERE c.expiresAt < :now")
    int deleteExpiredChallenges(LocalDateTime now);

    void deleteByEmail(String email);
}
