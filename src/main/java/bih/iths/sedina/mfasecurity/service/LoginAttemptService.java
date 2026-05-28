package bih.iths.sedina.mfasecurity.service;

import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class LoginAttemptService {

    private final int MAX_ATTEMPTS = 5;

    private final Map<String, Integer> attempts = new HashMap<>();

    public void loginFailed(String username) {
        int currentAttempts = attempts.getOrDefault(username, 0);
        attempts.put(username, currentAttempts + 1);
    }

    public void loginSucceeded(String username) {
        attempts.remove(username);
    }

    public boolean isBlocked(String username) {
        return attempts.getOrDefault(username, 0) >= MAX_ATTEMPTS;
    }
}
