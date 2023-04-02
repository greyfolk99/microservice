package com.greyfolk99.gatewayservice.filter;

import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

    @Value("${token.secretKey}")
    String secretKey;

    public AuthorizationHeaderFilter() {
        super(Config.class);
    }

    public static class Config {
        // Put the configuration properties for your filter here
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {

            ServerHttpRequest request = exchange.getRequest();

            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "No authorization in header", HttpStatus.BAD_REQUEST);
            } else if (!request.getHeaders().containsKey("userId")) {
                return onError(exchange, "No userId in header", HttpStatus.BAD_REQUEST);
            }

            String userId = request.getHeaders().get("userId").get(0);
            String token = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);

            if (!token.startsWith("Bearer ")) {
                return onError(exchange, "JWT token must starts with 'Bearer ' prefix", HttpStatus.BAD_REQUEST);
            }

            String jwt = token.replace("Bearer ", "");

            if (!isJwtValid(jwt, userId)) {
                return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
            }

            return chain.filter(exchange);

        });
    }

    private boolean isJwtValid(String jwt, String userId) {
        boolean returnValue = true;

        String subject = null;

        try {
            subject = Jwts.parser().setSigningKey(secretKey)
                    .parseClaimsJws(jwt).getBody()
                    .getSubject();
        } catch (Exception e) {
            returnValue = false;
        }

        if (subject == null || subject.isEmpty() || !subject.equals(userId)) {
            returnValue = false;
        }

        return returnValue;
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        log.error(err);
        return response.setComplete();
    }

}
