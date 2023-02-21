// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package plugin

import (
	"context"
	"time"

	"github.com/Azure/kubernetes-kms/pkg/config"
	"github.com/Azure/kubernetes-kms/pkg/metrics"

	k8spb "k8s.io/apiserver/pkg/storage/value/encrypt/envelope/v2alpha1"
	"k8s.io/klog/v2"
	"k8s.io/kms/encryption"
	"k8s.io/kms/service"
)

// KeyManagementServiceServer is a gRPC server.
type KeyManagementServiceServer struct {
	client   *encryption.LocalKEKService
	reporter metrics.StatsReporter
}

type Config struct {
	ConfigFilePath string
	KeyVaultName   string
	KeyName        string
	KeyVersion     string
	ManagedHSM     bool
	ProxyMode      bool
	ProxyAddress   string
	ProxyPort      int
}

// New creates an instance of the KMS Service Server.
func New(ctx context.Context, pc *Config) (*KeyManagementServiceServer, error) {
	cfg, err := config.GetAzureConfig(pc.ConfigFilePath)
	if err != nil {
		return nil, err
	}
	kvClient, err := newKeyVaultClient(cfg, pc.KeyVaultName, pc.KeyName, pc.KeyVersion, pc.ProxyMode, pc.ProxyAddress, pc.ProxyPort, pc.ManagedHSM)
	if err != nil {
		return nil, err
	}

	return &KeyManagementServiceServer{
		client:   encryption.NewLocalKEKService(kvClient),
		reporter: metrics.NewStatsReporter(),
	}, nil
}

func (s *KeyManagementServiceServer) Status(ctx context.Context, request *k8spb.StatusRequest) (*k8spb.StatusResponse, error) {
	resp, err := s.client.Status(ctx)
	if err != nil {
		return nil, err
	}
	return &k8spb.StatusResponse{
		Version: resp.Version,
		Healthz: resp.Healthz,
		KeyId:   resp.KeyID,
	}, nil
}

// Encrypt message
func (s *KeyManagementServiceServer) Encrypt(ctx context.Context, request *k8spb.EncryptRequest) (*k8spb.EncryptResponse, error) {
	start := time.Now()

	var err error
	defer func() {
		errors := ""
		status := metrics.SuccessStatusTypeValue
		if err != nil {
			status = metrics.ErrorStatusTypeValue
			errors = err.Error()
		}
		s.reporter.ReportRequest(ctx, metrics.EncryptOperationTypeValue, status, time.Since(start).Seconds(), errors)
	}()

	klog.V(2).InfoS("encrypt request started", "uid", request.Uid)
	resp, err := s.client.Encrypt(ctx, request.Uid, request.Plaintext)
	if err != nil {
		klog.ErrorS(err, "failed to encrypt", "uid", request.Uid)
		return &k8spb.EncryptResponse{}, err
	}
	klog.V(2).InfoS("encrypt request complete", "uid", request.Uid)
	return &k8spb.EncryptResponse{
		Ciphertext:  resp.Ciphertext,
		KeyId:       resp.KeyID,
		Annotations: resp.Annotations,
	}, nil
}

// Decrypt message
func (s *KeyManagementServiceServer) Decrypt(ctx context.Context, request *k8spb.DecryptRequest) (*k8spb.DecryptResponse, error) {
	start := time.Now()

	var err error
	defer func() {
		errors := ""
		status := metrics.SuccessStatusTypeValue
		if err != nil {
			status = metrics.ErrorStatusTypeValue
			errors = err.Error()
		}
		s.reporter.ReportRequest(ctx, metrics.DecryptOperationTypeValue, status, time.Since(start).Seconds(), errors)
	}()

	klog.V(2).InfoS("decrypt request started", "uid", request.Uid)
	req := &service.DecryptRequest{
		Ciphertext:  request.Ciphertext,
		KeyID:       request.KeyId,
		Annotations: request.Annotations,
	}
	plaintext, err := s.client.Decrypt(ctx, request.Uid, req)
	if err != nil {
		klog.ErrorS(err, "failed to decrypt", "uid", request.Uid)
		return &k8spb.DecryptResponse{}, err
	}
	klog.V(2).Info("decrypt request complete", "uid", request.Uid)
	return &k8spb.DecryptResponse{Plaintext: plaintext}, nil
}
