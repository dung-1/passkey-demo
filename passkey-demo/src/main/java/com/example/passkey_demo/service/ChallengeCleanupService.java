package com.example.passkey_demo.service;

import com.example.passkey_demo.repository.ChallengeRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
public class ChallengeCleanupService {

    private static final Logger logger = LoggerFactory.getLogger(ChallengeCleanupService.class);

    @Autowired
    private ChallengeRepository challengeRepository;

    /**
     * Cleanup expired challenges every 10 minutes
     * This prevents the challenges table from growing indefinitely
     */
    @Scheduled(fixedRate = 600000) // 10 minutes in milliseconds
    @Transactional
    public void cleanupExpiredChallenges() {
        try {
            LocalDateTime now = LocalDateTime.now();
            int deletedCount = challengeRepository.deleteExpiredChallenges(now);
            if (deletedCount > 0) {
                logger.info("Cleaned up {} expired challenges", deletedCount);
            }
        } catch (Exception e) {
            logger.error("Error during challenge cleanup", e);
        }
    }
}
