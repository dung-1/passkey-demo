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
     * Lấy challenge mới nhất (theo createdAt DESC) cho email và type Đảm bảo
     * lấy đúng challenge được tạo gần nhất
     */
    Optional<Challenge> findFirstByEmailAndTypeOrderByCreatedAtDesc(
            String email, Challenge.ChallengeType type);

    /**
     * Xóa tất cả challenge của user theo email và type Dùng để cleanup trước
     * khi tạo challenge mới
     */
    @Modifying
    void deleteAllByEmailAndType(String email, ChallengeType type);

    @Modifying
    @Query("DELETE FROM Challenge c WHERE c.expiresAt < :now")
    int deleteExpiredChallenges(LocalDateTime now);

    void deleteByEmail(String email);
}
