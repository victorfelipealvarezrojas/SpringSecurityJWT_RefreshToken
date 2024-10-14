package io.getarrays.userservice.security;

import io.getarrays.userservice.filter.CustomAuthenticationFilter;
import io.getarrays.userservice.filter.CustomAuthorizationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.security.config.http.SessionCreationPolicy.*;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;


    /**
     * @Propósito: Configura cómo Spring Security debe autenticar a los usuarios.
     *
     * En este caso, está configurando:
     * El **UserDetailsService** que Spring usará para cargar los detalles del usuario.
     * El **PasswordEncoder** que se usará para verificar las contraseñas.
     *
     *
     * Este método se enfoca en el "cómo" de la autenticación.
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
    }

    /**
     * @Propósito: Configura la seguridad a nivel de HTTP y la autorización.
     *
     * En este caso, está configurando:
     * Desactivación de CSRF.
     * Reglas de autorización para diferentes URLs y métodos HTTP.
     * Filtros personalizados para autenticación y autorización.
     *
     * Este método se enfoca en el "qué" de la seguridad: qué recursos están protegidos y quién puede acceder a ellos
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManagerBean());
        customAuthenticationFilter.setFilterProcessesUrl("/api/login");
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(STATELESS);
        http.authorizeRequests().antMatchers("/api/login/**", "/api/token/refresh/**").permitAll();
        http.authorizeRequests().antMatchers(GET, "/api/user/**").hasAnyAuthority("ROLE_USER");
        http.authorizeRequests().antMatchers(POST, "/api/user/save/**").hasAnyAuthority("ROLE_ADMIN");
        http.authorizeRequests().anyRequest().authenticated();
        http.addFilter(customAuthenticationFilter);
        http.addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    /**
     * @Propósito: Expone el AuthenticationManager como un bean en el contexto de Spring.
     *
     * Este método:
     * Hace que el AuthenticationManager esté disponible para su inyección en otros componentes.
     * Permite el uso del AuthenticationManager en filtros personalizados, como CustomAuthenticationFilter.
     * Mantiene la configuración de autenticación definida en configure(AuthenticationManagerBuilder).
     *
     * Este método se enfoca en proporcionar acceso al componente central de autenticación de Spring Security.
     */
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}


/**
 * @Concepto: AuthenticationManager
 *
 * @Definición: Es la interfaz principal en Spring Security responsable de procesar solicitudes de autenticación.
 *
 * @Funciones principales:
 * - Valida las credenciales de un usuario.
 * - Crea un objeto Authentication que representa al usuario autenticado si las credenciales son válidas.
 * - Lanza una AuthenticationException si la autenticación falla.
 *
 * @Uso típico:
 * - Es utilizado por filtros de seguridad para autenticar usuarios durante las solicitudes HTTP.
 * - Puede ser inyectado en componentes personalizados para realizar autenticación programática.
 *
 * @Implementación común:
 * ProviderManager, que delega a una lista de AuthenticationProvider para realizar la autenticación.
 *
 * @Relación con configure(AuthenticationManagerBuilder):
 * Este método configura el AuthenticationManager, especificando cómo debe validar las credenciales del usuario.
 */