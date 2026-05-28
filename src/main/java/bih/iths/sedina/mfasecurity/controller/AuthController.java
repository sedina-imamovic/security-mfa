package bih.iths.sedina.mfasecurity.controller;


import bih.iths.sedina.mfasecurity.model.AppUser;
import bih.iths.sedina.mfasecurity.repository.AppUserRepository;
import bih.iths.sedina.mfasecurity.service.LoginAttemptService;
import bih.iths.sedina.mfasecurity.service.QRCodeService;
import bih.iths.sedina.mfasecurity.service.TwoFactorService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class AuthController {
    @Autowired
    private PasswordEncoder passwordEncoder;

    private final AppUserRepository appUserRepository;
    private final TwoFactorService twoFactorService;
    private final QRCodeService qrCodeService;
    private final LoginAttemptService loginAttemptService;

    public AuthController(AppUserRepository appUserRepository,
                          TwoFactorService twoFactorService,
                          QRCodeService qrCodeService, LoginAttemptService loginAttemptService) {
        this.appUserRepository = appUserRepository;
        this.twoFactorService = twoFactorService;
        this.qrCodeService = qrCodeService;
        this.loginAttemptService = loginAttemptService;
    }

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @GetMapping("/register")
    public String registerPage() {
        return "register";
    }

    @PostMapping("/register")
    public String register(@RequestParam String username,
                           @RequestParam String password,
                           @RequestParam(required = false) Boolean use2fa,
                           HttpSession session,
                           RedirectAttributes redirectAttributes) {

        if (username == null || username.length() < 3) {
            redirectAttributes.addFlashAttribute("error",
                    "Username must contain at least 3 characters");
            return "redirect:/register";
        }

        if (password == null || password.length() < 8) {
            redirectAttributes.addFlashAttribute("error",
                    "Password must contain at least 8 characters");
            return "redirect:/register";
        }

        if (appUserRepository.findByUsername(username).isPresent()) {
            redirectAttributes.addFlashAttribute("error",
                    "Registration failed");
            return "redirect:/register";
        }

        AppUser appUser = new AppUser();
        appUser.setUsername(username.trim());
        appUser.setPassword(passwordEncoder.encode(password));

        if (Boolean.TRUE.equals(use2fa)) {
            String secret = twoFactorService.generateSecret();
            appUser.setSecret(twoFactorService.encryptSecret(secret));
            appUser.setTwoFactorEnabled(true);
            appUserRepository.save(appUser);

            session.setAttribute("registered_user", username);
            return "redirect:/qr";
        }

        appUser.setTwoFactorEnabled(false);
        appUserRepository.save(appUser);

        redirectAttributes.addFlashAttribute("success", "Registration successful! You can now log in.");
        return "redirect:/login";

    }

    @GetMapping("/qr")
    public String qrPage(HttpSession session, Model model) {
        String username = (String) session.getAttribute("registered_user");

        if (username == null || username.isEmpty()) {
            return "redirect:/register";
        }
        AppUser user = appUserRepository.findByUsername(username).orElse(null);

        if (user == null) {
            return "redirect:/register";
        }

        String secret = twoFactorService.decryptSecret(user.getSecret());
        String qrData = twoFactorService.getQRUrl(user.getUsername(), secret);
        String qrBase64 = qrCodeService.generateQRCodeBase64(qrData);

        model.addAttribute("qrImage", qrBase64);
        model.addAttribute("secret", secret);

        return "qr";
    }


    @GetMapping("/login")
    public String login(HttpSession session, Model model) {

        if (session.getAttribute("registered_user") != null) {
            model.addAttribute("success", "2FA setup complete! You can now log in!");
            session.removeAttribute("registered_user");
        }
        return "login";
    }

    @GetMapping("/post-login")
    public String postLogin(Authentication auth, HttpServletRequest request,
                            HttpSession session, HttpServletResponse response) {

        String username = auth.getName();

        if (loginAttemptService.isBlocked(username)) {
            SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
            logoutHandler.logout(request, response, auth);
            return "redirect:/login?blocked=true";
        }

        loginAttemptService.loginSucceeded(username);

        AppUser appUser = appUserRepository.findByUsername(username).orElse(null);

        if (appUser != null && appUser.isTwoFactorEnabled()) {
            session.setAttribute("2fa_verified", false);
            return "redirect:/verify-2fa";
        }

        session.setAttribute("2fa_verified", true);
        return "redirect:/welcome";
    }

    @GetMapping("/verify-2fa")
    public String verifyPage() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || "anonymousUser" .equals(auth.getPrincipal())) {
            return "redirect:/login";
        }
        return "verify-2fa";
    }

    @PostMapping("/verify-2fa")
    public String verify(@RequestParam String code, HttpSession session, Model model) {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || "anonymousUser" .equals(auth.getPrincipal())) {
            return "redirect:/login";
        }

        Integer attempts = (Integer) session.getAttribute("attempts");

        if (attempts == null) {
            attempts = 0;
        }

        if (attempts >= 5) {
            model.addAttribute("error", "Too many failed attempts. Try again later.");
            return "verify-2fa";
        }

        if (!code.matches("^[0-9]{6}$")) {
            model.addAttribute("error", "Invalid verification code");
            return "verify-2fa";
        }

        String username = auth.getName();
        AppUser appUser = appUserRepository.findByUsername(username).orElse(null);

        if (appUser == null) {
            return "redirect:/login";
        }

        String decryptedSecret = twoFactorService.decryptSecret(appUser.getSecret());
        boolean isValid = twoFactorService.verifyCode(decryptedSecret, Integer.parseInt(code));

        if (isValid) {
            session.removeAttribute("attempts");
            session.setAttribute("2fa_verified", true);
            return "redirect:/welcome";
        }

        session.setAttribute("attempts", attempts + 1);
        model.addAttribute("error", "Wrong verification code, try again");

        return "verify-2fa";
    }


}
