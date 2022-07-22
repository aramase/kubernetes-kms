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
	k8spb "github.com/Azure/kubernetes-kms/pkg/v2alpha1"
	"github.com/Azure/kubernetes-kms/pkg/version"

	"k8s.io/klog/v2"
)

// KeyManagementServiceServer is a gRPC server.
type KeyManagementServiceServer struct {
	kvClient Client
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
		kvClient: kvClient,
		reporter: metrics.NewStatsReporter(),
	}, nil
}

// Version of kms
func (s *KeyManagementServiceServer) Status(ctx context.Context, request *k8spb.StatusRequest) (*k8spb.StatusResponse, error) {
	return &k8spb.StatusResponse{
		Version: version.APIVersion,
		Healthz: "ok",
		KeyId:   s.kvClient.GetKeyID(),
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

	klog.V(2).Info("encrypt request started")
	ciphertext, err := s.kvClient.Encrypt(ctx, request.Plaintext)
	if err != nil {
		klog.ErrorS(err, "failed to encrypt")
		return &k8spb.EncryptResponse{}, err
	}
	klog.V(2).Info("encrypt request complete")
	return &k8spb.EncryptResponse{Ciphertext: ciphertext, KeyId: "kms-key-id", Annotations: map[string][]byte{"foo": []byte("bar")}}, nil
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

	klog.V(2).Info("decrypt request started")
	plaintext, err := s.kvClient.Decrypt(ctx, request.Ciphertext)
	if err != nil {
		klog.ErrorS(err, "failed to decrypt")
		return &k8spb.DecryptResponse{}, err
	}
	klog.V(2).Info("decrypt request complete")
	return &k8spb.DecryptResponse{Plaintext: plaintext}, nil
}
