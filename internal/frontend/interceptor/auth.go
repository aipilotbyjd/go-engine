package interceptor

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	authorizationHeader = "authorization"
	bearerPrefix        = "Bearer "
)

type AuthInterceptor struct {
	skipMethods map[string]bool
}

type AuthConfig struct {
	SkipMethods []string
}

func NewAuthInterceptor(cfg AuthConfig) *AuthInterceptor {
	skipMethods := make(map[string]bool)
	for _, method := range cfg.SkipMethods {
		skipMethods[method] = true
	}

	return &AuthInterceptor{
		skipMethods: skipMethods,
	}
}

func (a *AuthInterceptor) UnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	if a.skipMethods[info.FullMethod] {
		return handler(ctx, req)
	}

	token, err := a.extractToken(ctx)
	if err != nil {
		return nil, err
	}

	claims, err := a.ValidateToken(token)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}

	ctx = context.WithValue(ctx, claimsContextKey{}, claims)

	return handler(ctx, req)
}

func (a *AuthInterceptor) StreamInterceptor(
	srv interface{},
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	if a.skipMethods[info.FullMethod] {
		return handler(srv, ss)
	}

	token, err := a.extractToken(ss.Context())
	if err != nil {
		return err
	}

	_, err = a.ValidateToken(token)
	if err != nil {
		return status.Error(codes.Unauthenticated, "invalid token")
	}

	return handler(srv, ss)
}

func (a *AuthInterceptor) extractToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "missing metadata")
	}

	authHeaders := md.Get(authorizationHeader)
	if len(authHeaders) == 0 {
		return "", status.Error(codes.Unauthenticated, "missing authorization header")
	}

	authHeader := authHeaders[0]
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return "", status.Error(codes.Unauthenticated, "invalid authorization header format")
	}

	return strings.TrimPrefix(authHeader, bearerPrefix), nil
}

type Claims struct {
	Subject     string
	Namespace   string
	Permissions []string
}

func (a *AuthInterceptor) ValidateToken(token string) (*Claims, error) {
	if token == "" {
		return nil, status.Error(codes.Unauthenticated, "empty token")
	}

	return &Claims{
		Subject:     "user",
		Namespace:   "default",
		Permissions: []string{"read", "write"},
	}, nil
}

type claimsContextKey struct{}

func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey{}).(*Claims)
	return claims, ok
}
