package com.api.gateway.util;

import java.util.Base64;
import java.util.Date;
import java.util.function.Function;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

@Component
public class JwtUtil {

	@Value("${jwt.secret}")
	private String secret;

	@PostConstruct
	protected void init() {
		// this is to avoid having the raw secret key available in the JVM
		secret = Base64.getEncoder().encodeToString(secret.getBytes());
	}

	public Boolean validateToken(String token) {
		return !isTokenExpired(token);
	}

	private Boolean isTokenExpired(String token) {
		final Date expiration = getExpirationDateFromToken(token);
		return expiration.before(new Date());
	}

	public Date getExpirationDateFromToken(String token) {
		return getClaimFromToken(token, Claims::getExpiration);
	}

	public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = getAllClaimsFromToken(token);
		return claimsResolver.apply(claims);
	}

	private Claims getAllClaimsFromToken(String token) {
		return Jwts.parser()
				.setSigningKey(secret)
				.parseClaimsJws(token)
				.getBody();
	}
}