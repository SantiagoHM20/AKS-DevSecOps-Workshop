package com.vulnerable.vulnerableapp;

import java.security.Key;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.RestClientException;
import org.springframework.web.util.UriComponentsBuilder;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@RestController
public class HttpController {

    private static final Key JWT_SIGNING_KEY = buildJwtSigningKey();

    private static final String TRUSTED_REDIRECT_HOST = "localhost";
    private static final int TRUSTED_REDIRECT_PORT = 8080;

  @Autowired
  private EmployeeRepository employeeRepository;

  private static Key buildJwtSigningKey() {
    byte[] generatedSecret = new byte[32];
    new SecureRandom().nextBytes(generatedSecret);
    return Keys.hmacShaKeyFor(generatedSecret);
  }

  @GetMapping("/employees")
  public List<Employee> getAllEmployees() {
    JDBCManager.executeQuery("Blah blah");
    return employeeRepository.findAll();
  }

  @GetMapping("/employees/{id}")
  public Employee getEmployeeById(@PathVariable(value = "id") Long employeeId) {
    return employeeRepository.findById(employeeId)
        .orElseThrow(() -> new ResourceNotFoundException("Employee", "id", employeeId));
  }

  @GetMapping("/employeesDynamic/{id}")
  public Employee getEmployeeByDId(@PathVariable(value = "id") Long employeeId) {
    return employeeRepository.findByFilterText(employeeId).get(0);

  }

  @GetMapping("/employeesByDynamicSql/{query}")
  public List<Employee> getEmployeeByDynamicSQL(@PathVariable(value = "query") String queryToExecute) {
    List<Employee> employees = JDBCManager.executeQuery(queryToExecute);
    return employees;
  }

  @PostMapping("/employees")
  public Employee createEmployee(@RequestBody Employee employee) {
    return employeeRepository.save(employee);
  }

  /*
   * This method is vulnerable to JWT token manipulation
   */
  @RequestMapping(path = "/JWT/secret/gettoken", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getSecretToken() {
    return Jwts.builder()
      .issuer("test Corp")
      .audience().add("testvuln.org").and()
      .issuedAt(Date.from(Instant.now()))
      .expiration(Date.from(Instant.now().plusSeconds(60)))
      .subject("jak@test.com")
        .claim("username", "John")
        .claim("Email", "johndoe@test.com")
        .claim("Role", new String[] { "Manager", "Project Administrator" })
      .signWith(JWT_SIGNING_KEY)
        .compact();
  }

  /*
   * fake method to simulate clicking on the link in the email
   */
  private void fakeClickingLinkEmail(String resetLink) {
    try {
      HttpHeaders httpHeaders = new HttpHeaders();
      HttpEntity<Void> httpEntity = new HttpEntity<>(httpHeaders);
      String safeResetLink = resetLink == null ? "" : resetLink.replaceAll("[^a-zA-Z0-9_-]", "");
      String safeUrl = UriComponentsBuilder.newInstance()
          .scheme("http")
          .host(TRUSTED_REDIRECT_HOST)
          .port(TRUSTED_REDIRECT_PORT)
          .path("/PasswordReset/reset/reset-password/{resetLink}")
          .buildAndExpand(safeResetLink)
          .toUriString();
      new RestTemplate()
          .exchange(
              safeUrl,
              HttpMethod.GET,
              httpEntity,
              Void.class);
    } catch (RestClientException e) {

    }
  }

  @GetMapping("/employees/redirect")
  public void fakeRedirect(String ignoredHost, String resetLink) {
    fakeClickingLinkEmail(resetLink);
  }
}
