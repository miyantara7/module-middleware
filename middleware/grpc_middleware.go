package middleware

import (
	"Project/module-middleware/middleware/model"
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func (j *JWTManager) Verify(ctx context.Context) (*model.MetaData, error) {
	var metaData *model.MetaData
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return &model.MetaData{}, status.Errorf(codes.InvalidArgument, "UnaryEcho: failed to get metadata")
	}

	values := md["authorization"]
	if len(values) == 0 {
		return &model.MetaData{}, status.Errorf(codes.Unauthenticated, "authorization token is not provided")
	}

	claims, err := ValidateIDToken(values[0], j.secretKey)
	if err != nil {
		return &model.MetaData{}, err
	}

	metaData.UserID = claims.UserID
	metaData.UserName = claims.Name

	return metaData, nil
}
