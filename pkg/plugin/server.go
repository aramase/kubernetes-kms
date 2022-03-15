// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package plugin

import (
	"context"
	"time"

	"github.com/Azure/kubernetes-kms/pkg/config"
	"github.com/Azure/kubernetes-kms/pkg/encryption"
	"github.com/Azure/kubernetes-kms/pkg/encryption/aes"
	"github.com/Azure/kubernetes-kms/pkg/kek"
	"github.com/Azure/kubernetes-kms/pkg/keyvault"
	"github.com/Azure/kubernetes-kms/pkg/metrics"
	k8spb "github.com/Azure/kubernetes-kms/pkg/v2alpha1"
	"github.com/Azure/kubernetes-kms/pkg/version"

	"k8s.io/klog/v2"
)

// KeyManagementServiceServer is a gRPC server.
type KeyManagementServiceServer struct {
	reporter metrics.StatsReporter
	service  encryption.EncryptionService
}

// New creates an instance of the KMS Service Server.
func New(ctx context.Context, configFilePath, vaultName, keyName, keyVersion string, proxyMode bool, proxyAddress string, proxyPort int) (*KeyManagementServiceServer, error) {
	cfg, err := config.GetAzureConfig(configFilePath)
	if err != nil {
		return nil, err
	}
	kvClient, err := keyvault.NewClient(cfg, vaultName, keyName, keyVersion, proxyMode, proxyAddress, proxyPort)
	if err != nil {
		return nil, err
	}
	reporter := metrics.NewStatsReporter()
	kekService, err := kek.NewKEKService(kvClient, reporter)
	if err != nil {
		return nil, err
	}
	es, err := aes.NewAESCBCService(kekService)
	if err != nil {
		return nil, err
	}

	return &KeyManagementServiceServer{
		reporter: reporter,
		service:  es,
	}, nil
}

// Version of kms
func (s *KeyManagementServiceServer) Version(ctx context.Context, request *k8spb.VersionRequest) (*k8spb.VersionResponse, error) {
	return &k8spb.VersionResponse{
		Version:        version.APIVersion,
		RuntimeName:    version.Runtime,
		RuntimeVersion: version.BuildVersion,
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

	if string(request.Plain) != healthCheckPlainText && string(request.Plain) != "ping" {
		klog.V(2).InfoS("encrypt request started", "uid", request.Uid)
	}
	cipher, encKEK, err := s.service.Encrypt(ctx, request.Plain)
	if err != nil {
		klog.ErrorS(err, "failed to encrypt", "uid", request.Uid)
		return &k8spb.EncryptResponse{}, err
	}
	if string(request.Plain) != healthCheckPlainText {
		klog.V(2).InfoS("encrypt request complete", "uid", request.Uid)
	}
	return &k8spb.EncryptResponse{Cipher: cipher, Key: encKEK}, nil
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

	// klog.V(2).InfoS("decrypt request started", "uid", request.Uid, "key", string(request.Key))
	plain, err := s.service.Decrypt(ctx, request.Cipher, request.Key)
	if err != nil {
		klog.ErrorS(err, "failed to decrypt", "uid", request.Uid)
		return &k8spb.DecryptResponse{}, err
	}

	if string(plain) != healthCheckPlainText && string(plain) != "ping" {
		klog.V(2).InfoS("decrypt request complete", "uid", request.Uid)
	}
	return &k8spb.DecryptResponse{Plain: plain}, nil
}
