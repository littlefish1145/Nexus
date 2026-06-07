package sts_service

import (
	"context"

	pb "nexus/proto/sts"

	"go.uber.org/zap"
)

// GRPCAdapter adapts the STS service to gRPC interface
type GRPCAdapter struct {
	pb.UnimplementedSTSServiceServer
	service *STSService
}

// NewGRPCAdapter creates a new gRPC adapter for STS
func NewGRPCAdapter(service *STSService) *GRPCAdapter {
	return &GRPCAdapter{service: service}
}

// AssumeRole handles gRPC AssumeRole requests
func (a *GRPCAdapter) AssumeRole(ctx context.Context, req *pb.AssumeRoleRequest) (*pb.AssumeRoleResponse, error) {
	zap.L().Info("gRPC AssumeRole",
		zap.String("role_arn", req.RoleArn),
		zap.String("caller_arn", req.CallerArn))

	cred, err := a.service.AssumeRole(ctx, req.RoleArn, req.RoleSessionName, int(req.DurationSeconds), req.ExternalId, req.Policy, req.CallerArn)
	if err != nil {
		return nil, err
	}

	return &pb.AssumeRoleResponse{
		Credentials: &pb.Credentials{
			AccessKeyId:     cred.AccessKeyID,
			SecretAccessKey: cred.SecretAccessKey,
			SessionToken:    cred.SessionToken,
			ExpirationUnix:  cred.Expiration.Unix(),
		},
		AssumedRoleUserArn: req.RoleArn,
	}, nil
}

// GetSessionToken handles gRPC GetSessionToken requests
func (a *GRPCAdapter) GetSessionToken(ctx context.Context, req *pb.GetSessionTokenRequest) (*pb.GetSessionTokenResponse, error) {
	zap.L().Info("gRPC GetSessionToken", zap.String("caller_arn", req.CallerArn))

	cred, err := a.service.GetSessionToken(ctx, req.CallerArn, int(req.DurationSeconds))
	if err != nil {
		return nil, err
	}

	return &pb.GetSessionTokenResponse{
		Credentials: &pb.Credentials{
			AccessKeyId:     cred.AccessKeyID,
			SecretAccessKey: cred.SecretAccessKey,
			SessionToken:    cred.SessionToken,
			ExpirationUnix:  cred.Expiration.Unix(),
		},
	}, nil
}

// GetFederationToken handles gRPC GetFederationToken requests
func (a *GRPCAdapter) GetFederationToken(ctx context.Context, req *pb.GetFederationTokenRequest) (*pb.GetFederationTokenResponse, error) {
	zap.L().Info("gRPC GetFederationToken", zap.String("name", req.Name))

	cred, err := a.service.GetFederationToken(ctx, req.Name, req.CallerArn, int(req.DurationSeconds), req.Policy)
	if err != nil {
		return nil, err
	}

	return &pb.GetFederationTokenResponse{
		Credentials: &pb.Credentials{
			AccessKeyId:     cred.AccessKeyID,
			SecretAccessKey: cred.SecretAccessKey,
			SessionToken:    cred.SessionToken,
			ExpirationUnix:  cred.Expiration.Unix(),
		},
	}, nil
}
