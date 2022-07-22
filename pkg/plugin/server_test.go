// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package plugin

import (
	"context"
	"fmt"
	"testing"

	"github.com/Azure/kubernetes-kms/pkg/metrics"
	mockkeyvault "github.com/Azure/kubernetes-kms/pkg/plugin/mock_keyvault"
	k8spb "github.com/Azure/kubernetes-kms/pkg/v2alpha1"
	"github.com/Azure/kubernetes-kms/pkg/version"
)

func TestEncrypt(t *testing.T) {
	tests := []struct {
		desc   string
		input  []byte
		output []byte
		err    error
	}{
		{
			desc:   "failed to encrypt",
			input:  []byte("foo"),
			output: []byte{},
			err:    fmt.Errorf("failed to encrypt"),
		},
		{
			desc:   "successfully encrypted",
			input:  []byte("foo"),
			output: []byte("bar"),
			err:    nil,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			kvClient := &mockkeyvault.KeyVaultClient{}
			kvClient.SetEncryptResponse(test.output, test.err)

			kmsServer := KeyManagementServiceServer{
				kvClient: kvClient,
				reporter: metrics.NewStatsReporter(),
			}

			out, err := kmsServer.Encrypt(context.TODO(), &k8spb.EncryptRequest{
				Plaintext: test.input,
			})
			if err != test.err {
				t.Fatalf("expected err: %v, got: %v", test.err, err)
			}
			if string(out.GetCiphertext()) != string(test.output) {
				t.Fatalf("expected out: %v, got: %v", test.output, out)
			}
		})
	}
}

func TestDecrypt(t *testing.T) {
	tests := []struct {
		desc   string
		input  []byte
		output []byte
		err    error
	}{
		{
			desc:   "failed to decrypt",
			input:  []byte("foo"),
			output: []byte{},
			err:    fmt.Errorf("failed to decrypt"),
		},
		{
			desc:   "successfully decrypted",
			input:  []byte("bar"),
			output: []byte("foo"),
			err:    nil,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			kvClient := &mockkeyvault.KeyVaultClient{}
			kvClient.SetDecryptResponse(test.output, test.err)

			kmsServer := KeyManagementServiceServer{
				kvClient: kvClient,
				reporter: metrics.NewStatsReporter(),
			}

			out, err := kmsServer.Decrypt(context.TODO(), &k8spb.DecryptRequest{
				Ciphertext: test.input,
			})
			if err != test.err {
				t.Fatalf("expected err: %v, got: %v", test.err, err)
			}
			if string(out.GetPlaintext()) != string(test.output) {
				t.Fatalf("expected out: %v, got: %v", test.output, out)
			}
		})
	}
}

func TestStatus(t *testing.T) {
	kmsServer := KeyManagementServiceServer{}

	version.BuildVersion = "latest"

	v, err := kmsServer.Status(context.TODO(), &k8spb.StatusRequest{})
	if err != nil {
		t.Fatalf("expected err to be nil, got: %v", err)
	}
	if v.Version != version.APIVersion {
		t.Fatalf("expected version: %s, got: %s", version.APIVersion, v.Version)
	}
	if v.Healthz != "ok" {
		t.Fatalf("expected healthz: %s, got: %s", "ok", v.Healthz)
	}
	if v.KeyId != "1" {
		t.Fatalf("expected keyId: %s, got: %s", "", v.KeyId)
	}
}
