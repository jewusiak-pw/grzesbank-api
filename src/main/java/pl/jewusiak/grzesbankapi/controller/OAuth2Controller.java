package pl.jewusiak.grzesbankapi.controller;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.view.RedirectView;
import pl.jewusiak.grzesbankapi.model.mapper.ResponseMapper;
import pl.jewusiak.grzesbankapi.model.request.RegistrationRequest;
import pl.jewusiak.grzesbankapi.model.service.AuthService;

import java.util.List;
import java.util.Map;

import static org.springframework.security.web.context.HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;

@RestController
@RequestMapping("/auth/oauth2")
@RequiredArgsConstructor
@Slf4j
public class OAuth2Controller {

    private final AuthService authService;
    @Value("${pl.jewusiak.grzesbankapi.oauth2.webAppAuthUrl}")
    private String webAppAuthUrl;

    @GetMapping("/loginsuccess")
    public Object oAuthLoginRedirect(OAuth2AuthenticationToken authenticationToken, HttpSession session, HttpServletResponse response) {
        if (authenticationToken == null)
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "This is not an OAuth2 login flow!");
        Map<String, Object> attributes = authenticationToken.getPrincipal().getAttributes();

        var user = authService.authOauth2(attributes);
            SecurityContext sc = SecurityContextHolder.getContext();
            var auth = UsernamePasswordAuthenticationToken.authenticated(user.getEmail(), null, user.getAuthorities());
            sc.setAuthentication(auth);
            session.setAttribute(SPRING_SECURITY_CONTEXT_KEY, sc);
            return new RedirectView(webAppAuthUrl+"?result=true");
         
        //return new RedirectView(webAppAuthUrl+"?result=false");
    }
}
