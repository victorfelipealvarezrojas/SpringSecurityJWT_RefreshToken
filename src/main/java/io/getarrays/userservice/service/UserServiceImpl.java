package io.getarrays.userservice.service;

import io.getarrays.userservice.domain.Role;
import io.getarrays.userservice.domain.User;
import io.getarrays.userservice.repo.RoleRepo;
import io.getarrays.userservice.repo.UserRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {

    private final UserRepo userRepo;
    private final RoleRepo roleRepo;
    private final PasswordEncoder passwordEncoder;


    /**
     * @Propósito: Cargar los detalles del usuario para la autenticación en Spring Security.
     *
     * Este método:
     * - Busca un usuario en la base de datos por su nombre de usuario.
     * - Crea una colección de autoridades basada en los roles del usuario.
     * - Utiliza un método auxiliar para crear el objeto UserDetails de Spring Security.
     *
     * @param username El nombre de usuario para buscar en la base de datos.
     * @return UserDetails El objeto UserDetails de Spring Security con la información del usuario.
     * @throws UsernameNotFoundException Si no se encuentra el usuario en la base de datos.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepo.findByUsername(username);
        if(user == null) {
            log.error("User not found in the database");
            throw new UsernameNotFoundException("User not found in the database");
        } else {
            log.info("User found in the database: {}", username);
            Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
            user.getRoles().forEach(role -> {
                authorities.add(new SimpleGrantedAuthority(role.getName()));
            });
            return createUserDetails(user, authorities);
        }
    }

    @Override
    public User saveUser(User user) {
        log.info("Saving new user {} to the database", user.getName());
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepo.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("Saving new role {} to the database", role.getName());
        return roleRepo.save(role);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        log.info("Adding role {} to user {}", roleName, username);
        User user = userRepo.findByUsername(username);
        Role role = roleRepo.findByName(roleName);
        user.getRoles().add(role);
    }

    @Override
    public User getUser(String username) {
        log.info("Fetching user {}", username);
        return userRepo.findByUsername(username);
    }

    @Override
    public List<User> getUsers() {
        log.info("Fetching all users");
        return userRepo.findAll();
    }

    /**
     * @Propósito: Crear un objeto UserDetails de Spring Security a partir de un usuario personalizado.
     *
     * Este método:
     * - Encapsula la creación del objeto User de Spring Security.
     * - Evita el conflicto de nombres con la clase User personalizada.
     * - Proporciona una capa de abstracción entre el modelo de dominio y el modelo de seguridad.
     *
     * @param user El usuario personalizado de la aplicación.
     * @param authorities La colección de autoridades (roles) del usuario.
     * @return UserDetails Un objeto UserDetails de Spring Security con la información del usuario.
     */
    private UserDetails createUserDetails(User user, Collection<SimpleGrantedAuthority> authorities) {
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                authorities
        );
    }
}


/**
 * @Concepto: UserDetailsService y autenticación en Spring Security
 *
 * @Propósito principal:
 * Estos métodos definen el mecanismo para que Spring Security obtenga los detalles del usuario,
 * incluyendo su contraseña, para compararlos durante el proceso de autenticación.
 *
 * @Funcionamiento:
 * 1. loadUserByUsername:
 *    - Es llamado por Spring Security cuando un usuario intenta autenticarse.
 *    - Busca al usuario en la base de datos.
 *    - Recopila los roles/autoridades del usuario.
 *
 * 2. createUserDetails (método auxiliar):
 *    - Crea un objeto UserDetails de Spring Security.
 *    - Este objeto contiene la información necesaria para la autenticación y autorización.
 *
 * @Proceso de autenticación:
 * - Cuando un usuario intenta iniciar sesión, Spring Security llama a loadUserByUsername.
 * - Spring Security compara la contraseña proporcionada por el usuario con la almacenada en UserDetails.
 * - Si coinciden, la autenticación es exitosa; si no, falla.
 *
 * @Importancia:
 * Este mecanismo permite a Spring Security realizar la autenticación sin acceder directamente
 * a la base de datos o conocer los detalles de implementación de tu modelo de usuario.
 */
