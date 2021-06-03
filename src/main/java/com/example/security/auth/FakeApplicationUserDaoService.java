package com.example.security.auth;

import com.google.common.collect.Lists;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.example.security.security.ApplicationUserRole.*;

@RequiredArgsConstructor
@Repository("fake") // needs instantiate
public class FakeApplicationUserDaoService implements ApplicationUserDAO{

    @Autowired
    private final PasswordEncoder passwordEncoder;

    @Override
    public Optional<ApplicationUser> selectApplicationUserByName(String username) {
        return getApplicationUsers()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers(){
        return Lists.newArrayList(
                new ApplicationUser(
                        STUDENT.getGrantedAuthorities(),
                        "israel",
                        passwordEncoder.encode("12345"),
                        true,
                        true,
                        true,
                        true),
                new ApplicationUser(
                        ADMIN.getGrantedAuthorities(),
                        "monserrat",
                        passwordEncoder.encode("12345"),
                        true,
                        true,
                        true,
                        true),
                new ApplicationUser(
                        ADMINTRAINEE.getGrantedAuthorities(),
                        "tom",
                        passwordEncoder.encode("12345"),
                        true,
                        true,
                        true,
                        true)
        );
    }
}
