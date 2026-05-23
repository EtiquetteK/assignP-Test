package com.PracticalAssignment.assignP.service;

import com.PracticalAssignment.assignP.dto.LoginRequest;
import com.PracticalAssignment.assignP.dto.RegisterRequest;
import com.PracticalAssignment.assignP.model.User;
import com.PracticalAssignment.assignP.repository.UserRepository;
import com.PracticalAssignment.assignP.security.JwtUtil;
import com.PracticalAssignment.assignP.service.TokenBlacklistService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private TokenBlacklistService tokenBlacklistService;

    @InjectMocks
    private AuthService authService;

    private User testUser;
    private RegisterRequest registerRequest;
    private LoginRequest loginRequest;

    @BeforeEach
    void setUp() {
        testUser = new User();
        testUser.setId(1L);
        testUser.setUsername("testuser");
        testUser.setPassword("hashedPassword");
        testUser.setRole("MEMBER");

        registerRequest = new RegisterRequest();
        registerRequest.setUsername("newuser");
        registerRequest.setPassword("password123");

        loginRequest = new LoginRequest();
        loginRequest.setUsername("testuser");
        loginRequest.setPassword("password123");
    }

    @Test
    void testRegisterSuccess() {
        when(userRepository.findByUsername("newuser")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("password123")).thenReturn("hashedPassword");
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        var result = authService.register(registerRequest);

        assertNotNull(result);
        assertEquals("testuser", result.getUsername());
        verify(userRepository).save(any(User.class));
    }

    @Test
    void testRegisterDuplicateUsername() {
        when(userRepository.findByUsername("newuser")).thenReturn(Optional.of(testUser));

        assertThrows(ResponseStatusException.class, () -> authService.register(registerRequest));
    }

    @Test
    void testLoginSuccess() {
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("password123", "hashedPassword")).thenReturn(true);
        when(jwtUtil.generateToken("testuser", "MEMBER")).thenReturn("validToken");

        var result = authService.login(loginRequest);

        assertNotNull(result);
        assertEquals("validToken", result.getToken());
        assertEquals("MEMBER", result.getRole());
    }

    @Test
    void testLoginInvalidPassword() {
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("password123", "hashedPassword")).thenReturn(false);

        assertThrows(ResponseStatusException.class, () -> authService.login(loginRequest));
    }

    @Test
    void testLogoutBlacklistsToken() {
        String token = "testToken";
        authService.logout(token);

        verify(tokenBlacklistService).blacklistToken(token);
    }
}
