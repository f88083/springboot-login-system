package com.simonlai.springbootloginsystem.payload.request;

import com.simonlai.springbootloginsystem.model.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.util.Set;

@Data
public class SignupRequest {

    @NotBlank
    @Size(min = 3, max = 20)
    private String username;

    @NotBlank
    @Size(max = 50)
    @Email
    private String email;

    private Set<Role> role;

    @NotBlank
    @Size(min = 6, max = 20)
    private String password;
}
