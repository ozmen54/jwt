package com.sau.jwt.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Data
@Entity
@Table(name="user")
public class User {
    @Id
    @Column(length = 16)
    private String username;
    @Column(nullable = false, length = 255)
    private String password;
    @Column(length = 16)
    private String name;
    @Column(nullable = false, length = 16)
    private String role;
    @Column(name="is_locked", columnDefinition = "boolean default false")
    private boolean isLocked;
}
