package pl.jewusiak.grzesbankapi.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import pl.jewusiak.grzesbankapi.model.mapper.ResponseMapper;
import pl.jewusiak.grzesbankapi.model.request.ChangePasswordWithTokenRequest;
import pl.jewusiak.grzesbankapi.model.request.LoginRequest;
import pl.jewusiak.grzesbankapi.model.request.RegistrationRequest;
import pl.jewusiak.grzesbankapi.model.response.BasicUserInfoResponse;
import pl.jewusiak.grzesbankapi.model.response.PasswordCombinationResponse;
import pl.jewusiak.grzesbankapi.model.service.AccessLimitsService;
import pl.jewusiak.grzesbankapi.model.service.AuthService;
import pl.jewusiak.grzesbankapi.model.service.UserService;
import pl.jewusiak.grzesbankapi.utils.EasterEggHandler;
import pl.jewusiak.grzesbankapi.utils.ValidationService;

import java.util.UUID;

import static org.springframework.security.web.context.HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {
    private final AuthService authService;
    private final UserService userService;
    private final ResponseMapper responseMapper;
    private final AccessLimitsService accessLimitsService;

    @GetMapping("/login")
    @SneakyThrows
    public ResponseEntity<PasswordCombinationResponse> getPasswordCombinations(@RequestParam @Pattern(regexp = ValidationService.emailRegex) @NotBlank String email) {
        Thread.sleep(1500);
        return ResponseEntity.ok(authService.getRandomPasswordCombination(email));        
    }

    @PostMapping("/login")
    @SneakyThrows
    public ResponseEntity<?> auth(@RequestBody @Valid LoginRequest loginRequest, HttpSession session, HttpServletRequest request) {
        Thread.sleep(1500);
        var userOpt = authService.auth(loginRequest.getPcid(), loginRequest.getEmail(), loginRequest.getPassword());
        if(userOpt.isPresent()) {
            SecurityContext sc = SecurityContextHolder.getContext();
            var auth = UsernamePasswordAuthenticationToken.authenticated(userOpt.get().getEmail(), null, userOpt.get().getAuthorities());
            sc.setAuthentication(auth);
            session.setAttribute(SPRING_SECURITY_CONTEXT_KEY, sc);
            return ResponseEntity.ok(responseMapper.map(userOpt.get()));
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid login credentials");
    }
    
    @PostMapping("/register")
    @SneakyThrows
    public ResponseEntity<?> register(@RequestBody @Valid RegistrationRequest request) {
        Thread.sleep(1500);
        authService.register(request);
        return ResponseEntity.ok("OK");
    }
    
    @PostMapping("/resetpassword")
    @SneakyThrows
    public ResponseEntity<?> resetPassword(@RequestParam @Pattern(regexp = ValidationService.emailRegex) @NotBlank String email) {
        Thread.sleep(1500);
        authService.generatePasswordResetRequest(email);
        return ResponseEntity.ok("OK");
    }
    
    @PutMapping("/resetpassword")
    @SneakyThrows
    public ResponseEntity<?> doResetPassword(@RequestBody @Valid ChangePasswordWithTokenRequest request) {
        Thread.sleep(1500);
        authService.changePasswordWithToken(request.getToken(), request.getPassword());
        return ResponseEntity.ok("OK");
    }
    
    @GetMapping("/ip")
    public String ip(HttpServletRequest request) {
        String ip = request.getRemoteAddr();
        return ip;
    }
}
