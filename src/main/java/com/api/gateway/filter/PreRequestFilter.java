package com.api.gateway.filter;

import com.api.gateway.RouteValidator;
import com.api.gateway.util.EncryptDecrypt;
import com.api.gateway.util.JwtUtil;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.extern.log4j.Log4j2;
import org.bouncycastle.util.Strings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.factory.rewrite.MessageBodyDecoder;
import org.springframework.cloud.gateway.filter.factory.rewrite.MessageBodyEncoder;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import static java.util.function.Function.identity;

@Component
@Log4j2
public class PreRequestFilter extends AbstractGatewayFilterFactory<PreRequestFilter.Config> implements GatewayFilter {

    @Autowired
    private RouteValidator validator;

    @Autowired
    private JwtUtil jwtUtil;

    private Map<String, MessageBodyDecoder> messageBodyDecoders;
    private Map<String, MessageBodyEncoder> messageBodyEncoders;

    public PreRequestFilter() {
        super(Config.class);
    }

    public PreRequestFilter(Set<MessageBodyDecoder> messageBodyDecoders, Set<MessageBodyEncoder> messageBodyEncoders) {
        super(Config.class);
        this.messageBodyDecoders = messageBodyDecoders.stream().collect(Collectors.toMap(MessageBodyDecoder::encodingType, identity()));
        this.messageBodyEncoders = messageBodyEncoders.stream().collect(Collectors.toMap(MessageBodyEncoder::encodingType, identity()));
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> chain.filter(exchange));
    }

    public static class Config {
        public Config() {
        }
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        log.debug("Filtering request");
        ServerHttpRequest request = exchange.getRequest();
        if (validator.isSecured.test(request)) {
            if (this.isAuthMissing(request)) {
                return this.onError(exchange, HttpStatus.UNAUTHORIZED);
            }
            final String token = this.getAuthHeader(request);
            try {
                if (!jwtUtil.validateToken(token)) {
                    return this.onError(exchange, HttpStatus.UNAUTHORIZED);
                }
            } catch (ExpiredJwtException jwtException) {
                log.debug("Exception occurred", jwtException);
                return this.onError(exchange, HttpStatus.UNAUTHORIZED);
            }
        }
        return DataBufferUtils.join(exchange.getRequest().getBody()).flatMap(dataBuffer -> {
            ServerHttpRequest mutatedHttpRequest = null;
            try {
                mutatedHttpRequest = getServerHttpRequest(exchange, dataBuffer);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            return chain.filter(exchange.mutate().request(mutatedHttpRequest).build());
        });
    }

    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        return response.setComplete();
    }

    private String getAuthHeader(ServerHttpRequest request) {
        return request.getHeaders().getOrEmpty(HttpHeaders.AUTHORIZATION).get(0).substring(7);
    }

    private boolean isAuthMissing(ServerHttpRequest request) {
        return !request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION);
    }

    private ServerHttpRequest getServerHttpRequest(ServerWebExchange exchange, DataBuffer dataBuffer) throws Exception {
        DataBufferUtils.retain(dataBuffer);
        Flux<DataBuffer> cachedFlux = Flux.defer(() -> Flux.just(dataBuffer.slice(0, dataBuffer.readableByteCount())));
        String body = toRaw(cachedFlux);
        String decryptedBody = EncryptDecrypt.decrypt(body);
        byte[] decryptedBodyBytes = decryptedBody.getBytes(StandardCharsets.UTF_8);

        return new ServerHttpRequestDecorator(exchange.getRequest()) {
            @Override
            public HttpHeaders getHeaders() {
                HttpHeaders httpHeaders = new HttpHeaders();
                httpHeaders.putAll(exchange.getRequest().getHeaders());
                if (decryptedBodyBytes.length > 0) {
                    httpHeaders.setContentLength(decryptedBodyBytes.length);
                }
                httpHeaders.set(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON.toString());
                return httpHeaders;
            }
            @Override
            public Flux<DataBuffer> getBody() {
                return Flux.just(body).map(s -> {
                    return new DefaultDataBufferFactory().wrap(decryptedBodyBytes);
                });
            }
        };
    }

    private static String toRaw(Flux<DataBuffer> body) {
        AtomicReference<String> rawRef = new AtomicReference<>();
        body.subscribe(buffer -> {
            byte[] bytes = new byte[buffer.readableByteCount()];
            buffer.read(bytes);
            DataBufferUtils.release(buffer);
            rawRef.set(Strings.fromUTF8ByteArray(bytes));
        });
        return rawRef.get().replace("\"", "");
    }
}