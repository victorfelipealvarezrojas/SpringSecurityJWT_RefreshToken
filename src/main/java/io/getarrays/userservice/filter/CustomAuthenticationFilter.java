package io.getarrays.userservice.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;


/**
 * @Propósito: Filtro personalizado para manejar el proceso de autenticación en Spring Security.
 *
 * Esta clase:
 * - Extiende UsernamePasswordAuthenticationFilter para personalizar el proceso de autenticación.
 * - Maneja la autenticación basada en nombre de usuario y contraseña.
 * - Genera tokens JWT (access y refresh) tras una autenticación exitosa.
 *
 * @Componentes principales:
 * - AuthenticationManager: Utilizado para realizar la autenticación.
 * - attemptAuthentication: Procesa los intentos de autenticación.
 * - successfulAuthentication: Maneja la respuesta tras una autenticación exitosa.
 *
 * @Funcionalidad:
 * - Extrae username y password de la solicitud HTTP.
 * - Intenta autenticar al usuario usando AuthenticationManager.
 * - En caso de éxito, genera tokens JWT y los envía en la respuesta.
 *
 * @Seguridad:
 * - Utiliza JWT para la generación de tokens seguros.
 * - Incluye roles del usuario en el token de acceso para autorización.
 * - Define tiempos de expiración diferentes para tokens de acceso y refresco.
 *
 * @Nota: La clave secreta para JWT ("secret") debería ser manejada de forma más segura en un entorno de producción.
 */
@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    // Inyecta el AuthenticationManager, ObjectMapper para realizar la autenticación mediante X-WWW-Form-UrlEncoded o JSON.
    private final AuthenticationManager authenticationManager;
    private ObjectMapper objectMapper = new ObjectMapper();

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager, ObjectMapper objectMapper) {
        this.authenticationManager = authenticationManager;
        this.objectMapper = objectMapper;
    }





    /**
     * @Propósito: Procesa los intentos de autenticación en la solicitud HTTP.
     *
     * @Funcionamiento:
     * 1. Extrae username y password de la solicitud HTTP.
     * 2. Crea un UsernamePasswordAuthenticationToken con estas credenciales.
     * 3. Delega la autenticación al AuthenticationManager.
     * 4. El AuthenticationManager utiliza el UserDetailsService y PasswordEncoder configurados.
     * 5. Si la autenticación es exitosa, se crea un objeto Authentication completo.
     *
     * @Parámetros:
     * - request: Solicitud HTTP que contiene los datos de autenticación.
     * - response: Respuesta HTTP para enviar la respuesta de autenticación.
     *
     * @Excepciones:
     * - Lanza una excepción si la autenticación falla.
     *
     * @Retorno: Devuelve un objeto Authentication tras la autenticación exitosa.
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username, password;

        // Intenta obtener las credenciales de los parámetros de la solicitud por X-WWW-Form-UrlEncoded.
        // X-WWW-Form-UrlEncoded es un tipo de codificación de datos en solicitudes HTTP.
        username = request.getParameter("username");
        password = request.getParameter("password");

        // Si no se encuentran en los parámetros, intenta leer del cuerpo de la solicitud  por JSON.
        if (username == null || password == null) {
            try {
                Map<String, String> jsonRequest = new ObjectMapper().readValue(request.getInputStream(), Map.class);
                username = jsonRequest.get("username");
                password = jsonRequest.get("password");
            } catch (IOException e) {
                throw new AuthenticationServiceException("Failed to parse authentication request body", e);
            }
        }

        if (username == null || password == null) {
            throw new AuthenticationServiceException("Username or password not provided");
        }

        log.info("Username is: {}", username);
        log.info("Password is: {}", password);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        return authenticationManager.authenticate(authenticationToken);
    }

    /**
     * @Propósito: Maneja la respuesta tras una autenticación exitosa.
     *
     * Este método:
     * - Genera tokens JWT (access y refresh) tras una autenticación exitosa.
     * - Incluye roles del usuario en el token de acceso para autorización.
     * - Envía los tokens en la respuesta HTTP.
     *
     * @Funcionamiento:
     * 1. Se ejecuta solo si attemptAuthentication fue exitoso.
     * 2. Obtiene el User (Principal) del objeto Authentication.
     * 3. Genera dos tokens JWT:
     *    - access_token: para acceso a recursos protegidos.
     *    - refresh_token: para obtener nuevos access_token.
     * 4. Incluye información del usuario (username, roles) en los tokens.
     * 5. Establece tiempos de expiración para ambos tokens.
     * 6. Envía los tokens como respuesta en formato JSON.
     *
     * @Parámetros:
     * - request: Solicitud HTTP que contiene los datos de autenticación.
     * - response: Respuesta HTTP para enviar la respuesta de autenticación.
     * - chain: Cadena de filtros para continuar con la solicitud.
     * - authentication: Objeto Authentication tras la autenticación exitosa.
     *
     * @Excepciones:
     * - Lanza una excepción si la generación de tokens falla.
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
        User user = (User)authentication.getPrincipal();
        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
        String access_token = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(algorithm);
        String refresh_token = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 30 * 60 * 1000))
                .withIssuer(request.getRequestURL().toString())
                .sign(algorithm);

        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", access_token);
        tokens.put("refresh_token", refresh_token);
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), tokens); // Envía los tokens en la respuesta HTTP.
    }
}
