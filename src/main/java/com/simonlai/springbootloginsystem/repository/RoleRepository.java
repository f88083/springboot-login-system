package com.simonlai.springbootloginsystem.repository;

import com.simonlai.springbootloginsystem.model.ERole;
import com.simonlai.springbootloginsystem.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
