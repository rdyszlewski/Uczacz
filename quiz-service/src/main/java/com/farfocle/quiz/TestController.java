package com.farfocle.quiz;

import com.farfocle.quiz.security.User;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = "/test", produces = "application/json")
public class TestController {

    @GetMapping(path = "/{userId}")
    @PreAuthorize("#principal.getId().equals(#userId)")
    public String testGet(@PathVariable Long userId, @AuthenticationPrincipal User principal)
    {
        return "Dzień dobry " + userId;
    }
}
