package bih.iths.sedina.mfasecurity.controller;

import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping
public class WelcomeController {

    @GetMapping("/welcome")
    public String welcomePage(HttpSession session, Model model, Authentication auth) {

        Boolean verified = (Boolean) session.getAttribute("2fa_verified");

        if (verified == null || !verified) {
            return "redirect:/login";
        }

        if (auth != null) {
            model.addAttribute("username", auth.getName());
        }

        return "welcome";
    }


}
