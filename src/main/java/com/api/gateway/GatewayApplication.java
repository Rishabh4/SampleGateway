package com.api.gateway;

import com.api.gateway.filter.PreRequestFilter;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.cloud.gateway.filter.ratelimit.RedisRateLimiter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;

import com.api.gateway.filter.AuthenticationFilter;

import org.springframework.http.HttpMethod;
import reactor.core.publisher.Mono;

@SpringBootApplication
@Log4j2
public class GatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(GatewayApplication.class, args);
	}

	@Bean
	public KeyResolver keyResolver() {
		log.debug("Initializing Key Resolver");
		return exchange -> Mono.just(exchange.getRequest().getRemoteAddress().getAddress().getHostAddress());
	}

	@Autowired
	AuthenticationFilter abstractGatewayFilterFactory;

	@Autowired
	PreRequestFilter preRequestFilterFactory;

	@Bean
	RedisRateLimiter requestRateLimiter() {
		log.debug("Setting rate limiter");
		return new RedisRateLimiter(1, 1, 1);
	}

	@Bean
	public RouteLocator myRoutes(RouteLocatorBuilder builder) {
		log.debug("Setting Routes");
		return builder.routes()
				.route(r -> r.path("/signIn", "/register")
						.filters(f -> f.filter(preRequestFilterFactory))
						.uri("http://localhost:8081"))
				.route(r -> r.path("/**").and().method(HttpMethod.GET)
						.filters(f -> f.filter(abstractGatewayFilterFactory).requestRateLimiter(
								l -> l.setRateLimiter(requestRateLimiter()).setKeyResolver(keyResolver())))
						.uri("http://localhost:8081"))
				.route(r -> r.path("/**")
						.filters(f -> f.filter(preRequestFilterFactory).filter(abstractGatewayFilterFactory).requestRateLimiter(
								l -> l.setRateLimiter(requestRateLimiter()).setKeyResolver(keyResolver())))
						.uri("http://localhost:8081"))
				.build();
	}

}
