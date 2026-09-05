package com.otilm.cp.soft.api.v2;

import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.cp.soft.ExceptionHandlingAdvice;
import jakarta.servlet.http.HttpServletRequest;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.condition.PathPatternsRequestCondition;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.servlet.resource.NoResourceFoundException;
import org.springframework.web.util.ServletRequestPathUtils;
import org.springframework.web.util.pattern.PathPattern;

/**
 * Answers a V2 request that never reached an operation as a problem document.
 *
 * <p>
 * A method, a media type or a path the route does not serve is refused before any controller is chosen, so an advice
 * scoped to the V2 controllers cannot see it: with no controller there is no package to scope by, and the failure would
 * otherwise be answered by the connector-wide advice, in the V1 error shape and as an internal error. Which generation
 * the request belongs to is therefore decided here, and a request that is not a V2 one is handed to the connector-wide
 * advice so the V1 surface answers exactly as it did before.
 * </p>
 *
 * <p>
 * A route the connector serves says which generation it belongs to, so the routes themselves are asked rather than the
 * path being matched against a prefix written down here — the V2 interfaces are not all under one. A path that matches
 * no route at all has no generation to read, and there the prefix is the only thing left to go on.
 * </p>
 */
@Order(Ordered.HIGHEST_PRECEDENCE)
@RestControllerAdvice
public class V2DispatchFailureAdvice {

    /** The package the V2 controllers live in, which is what makes a route one of theirs. */
    private static final String V2_CONTROLLERS = "com.otilm.cp.soft.api.v2";

    /** Where the V2 interfaces are, for a path that matches no route and so names no controller. */
    private static final String V2_ROOT = "/v2";

    private final ObjectProvider<RequestMappingHandlerMapping> routes;

    private final ExceptionHandlingAdvice connectorWide;

    private final AtomicReference<Set<PathPattern>> v2Routes = new AtomicReference<>();

    public V2DispatchFailureAdvice(ObjectProvider<RequestMappingHandlerMapping> routes,
            ExceptionHandlingAdvice connectorWide) {
        this.routes = routes;
        this.connectorWide = connectorWide;
    }

    /**
     * A method the route does not serve. The methods it does serve are named back, which is what a caller reading a
     * refusal of this kind looks for.
     */
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<Object> handleMethodNotSupported(HttpRequestMethodNotSupportedException e,
            HttpServletRequest request) {
        if (!servesV2(request)) {
            return connectorWide.handleAll(e);
        }
        return problem(ErrorCode.OPERATION_NOT_SUPPORTED, "This route does not serve that method.",
                HttpStatus.METHOD_NOT_ALLOWED, allowing(e));
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<Object> handleMediaTypeNotSupported(HttpMediaTypeNotSupportedException e,
            HttpServletRequest request) {
        return servesV2(request)
                ? problem(ErrorCode.BAD_REQUEST, "The request body is not in a media type this route reads.",
                        HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                : connectorWide.handleAll(e);
    }

    @ExceptionHandler(HttpMediaTypeNotAcceptableException.class)
    public ResponseEntity<Object> handleMediaTypeNotAcceptable(HttpMediaTypeNotAcceptableException e,
            HttpServletRequest request) {
        return servesV2(request)
                ? problem(ErrorCode.BAD_REQUEST, "This route answers in no media type the request accepts.",
                        HttpStatus.NOT_ACCEPTABLE)
                : connectorWide.handleAll(e);
    }

    /**
     * A path this connector serves nothing under. Nothing names the generation it was meant for, so the V2 interfaces
     * answer for what is addressed to them and the rest is left as it was.
     */
    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<Object> handleNoSuchRoute(NoResourceFoundException e, HttpServletRequest request) {
        return isAddressedToV2(path(request))
                ? problem(ErrorCode.RESOURCE_NOT_FOUND, "This connector serves nothing under that path.",
                        HttpStatus.NOT_FOUND)
                : connectorWide.handleAll(e);
    }

    private static ResponseEntity<Object> problem(ErrorCode errorCode, String detail, HttpStatus status) {
        return problem(errorCode, detail, status, new HttpHeaders());
    }

    private static ResponseEntity<Object> problem(ErrorCode errorCode, String detail, HttpStatus status,
            HttpHeaders headers) {
        return ResponseEntity.status(status).headers(headers).body(V2Problem.document(errorCode, detail, status));
    }

    /** The methods the route does serve, where it says which they are. */
    private static HttpHeaders allowing(HttpRequestMethodNotSupportedException e) {
        Set<HttpMethod> served = Stream
                .ofNullable(e.getSupportedMethods())
                .flatMap(Stream::of)
                .map(HttpMethod::valueOf)
                .collect(Collectors.toCollection(LinkedHashSet::new));

        HttpHeaders headers = new HttpHeaders();
        if (!served.isEmpty()) {
            headers.setAllow(served);
        }
        return headers;
    }

    /** Whether a V2 route is what the request addressed, read off the routes this connector actually serves. */
    private boolean servesV2(HttpServletRequest request) {
        if (!ServletRequestPathUtils.hasParsedRequestPath(request)) {
            return isAddressedToV2(path(request));
        }
        var addressed = ServletRequestPathUtils.getParsedRequestPath(request).pathWithinApplication();
        return v2Routes().stream().anyMatch(route -> route.matches(addressed));
    }

    /**
     * The routes the V2 controllers serve. They are fixed once the application is running, so they are read once; the
     * mappings are asked for on first use rather than injected, since an advice is built before them. Every mapping is
     * asked, since more than one serves this connector.
     */
    private Set<PathPattern> v2Routes() {
        Set<PathPattern> known = v2Routes.get();
        if (known == null) {
            known = routes
                    .stream()
                    .map(RequestMappingHandlerMapping::getHandlerMethods)
                    .flatMap(served -> served.entrySet().stream())
                    .filter(V2DispatchFailureAdvice::isV2Controller)
                    .map(Map.Entry::getKey)
                    .flatMap(V2DispatchFailureAdvice::patternsOf)
                    .collect(Collectors.toUnmodifiableSet());
            v2Routes.compareAndSet(null, known);
        }
        return known;
    }

    private static boolean isV2Controller(Map.Entry<RequestMappingInfo, HandlerMethod> route) {
        return route.getValue().getBeanType().getPackageName().startsWith(V2_CONTROLLERS);
    }

    private static Stream<PathPattern> patternsOf(RequestMappingInfo route) {
        PathPatternsRequestCondition patterns = route.getPathPatternsCondition();
        return patterns == null ? Stream.empty() : patterns.getPatterns().stream();
    }

    /** Whether the path is under the V2 namespace, which the namespace root itself is. */
    private static boolean isAddressedToV2(String path) {
        return path.equals(V2_ROOT) || path.startsWith(V2_ROOT + "/");
    }

    private static String path(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String context = request.getContextPath();
        return context != null && !context.isEmpty() && uri.startsWith(context) ? uri.substring(context.length()) : uri;
    }
}
