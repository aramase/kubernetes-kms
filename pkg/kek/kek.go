package kek

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/Azure/kubernetes-kms/pkg/keyvault"
	"github.com/Azure/kubernetes-kms/pkg/metrics"

	"k8s.io/klog/v2"
	"k8s.io/utils/lru"
)

type KeyEncryptionKeyService interface {
	Get(ctx context.Context, encKEK []byte) (kek, encKey []byte, err error)
}

type kekService struct {
	mutex sync.Mutex

	kv keyvault.Client
	// transformers is a thread-safe LRU cache which caches decrypted KEKs indexed by their encrypted form.
	transformers *lru.Cache
	// encryptKEK is the current encrypt key.
	encryptedKEK      string
	encryptOperations int
	reporter          metrics.StatsReporter
}

// TODO: add counter for number of times key can be used for encrypt
func NewKEKService(kv keyvault.Client, reporter metrics.StatsReporter) (KeyEncryptionKeyService, error) {
	// generate the encrypt key
	encryptKey, err := generateKey(32)
	if err != nil {
		return nil, err
	}
	transformers := lru.New(1000)
	// encrypt the encrypt key
	encryptedKEK, err := kv.Encrypt(context.TODO(), encryptKey)
	if err != nil {
		return nil, err
	}
	// Use base64 of encKey as the key into the cache because hashicorp/golang-lru
	// cannot hash []uint8.
	transformers.Add(base64.StdEncoding.EncodeToString(encryptedKEK), encryptKey)

	return &kekService{
		// TODO: make this configurable
		transformers:      transformers,
		encryptedKEK:      base64.StdEncoding.EncodeToString(encryptedKEK),
		kv:                kv,
		encryptOperations: 0,
		reporter:          reporter,
	}, nil
}

func (s *kekService) Get(ctx context.Context, encKEK []byte) ([]byte, []byte, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if encKEK == nil {
		// this is for the case where we are encrypting the key
		s.encryptOperations++

		if s.encryptOperations < 5 {
			k := s.encryptedKEK
			if kek, ok := s.transformers.Get(k); ok {
				klog.InfoS("KEK found in cache", "operation", "encrypt", "count", s.encryptOperations)
				encKey, _ := base64.StdEncoding.DecodeString(k)
				return kek.([]byte), encKey, nil
			}
			return nil, nil, fmt.Errorf("encrypt key not found")
		}

		klog.InfoS("Rotating KEK", "operation", "encrypt")
		// rotate the encrypt key
		k, encryptKey, err := s.rotateEncryptKey()
		if err != nil {
			return nil, nil, err
		}
		s.encryptedKEK = k
		s.encryptOperations = 0
		encKey, _ := base64.StdEncoding.DecodeString(k)
		return encryptKey, encKey, nil
	}

	start := time.Now()
	var k string
	k = s.encryptedKEK
	if encKEK != nil {
		k = base64.StdEncoding.EncodeToString(encKEK)
	}

	if kek, ok := s.transformers.Get(k); ok {
		klog.InfoS("KEK found in cache", "operation", "decrypt")
		encKey, _ := base64.StdEncoding.DecodeString(k)
		return kek.([]byte), encKey, nil
	}

	klog.InfoS("KEK not found in cache, decrypting", "operation", "decrypt")
	// not in the cache, so decrypt the key and add it to the cache
	kek, err := s.kv.Decrypt(ctx, encKEK)
	if err != nil {
		return nil, nil, err
	}
	s.reporter.ReportRequest(context.TODO(), metrics.KMSDecryptOperationTypeValue, metrics.SuccessStatusTypeValue, time.Since(start).Seconds(), "")
	s.transformers.Add(k, kek)
	encKey, _ := base64.StdEncoding.DecodeString(k)
	klog.InfoS("KEK added to cache", "operation", "decrypt")
	return kek, encKey, nil
}

// generateKey generates a random key using system randomness.
func generateKey(length int) (key []byte, err error) {
	key = make([]byte, length)
	if _, err = rand.Read(key); err != nil {
		return nil, err
	}

	return key, nil
}

func (s *kekService) rotateEncryptKey() (string, []byte, error) {
	start := time.Now()
	// generate the new encrypt key
	encryptKey, err := generateKey(32)
	if err != nil {
		return "", nil, err
	}
	// encrypt the new encrypt key
	encryptedKEK, err := s.kv.Encrypt(context.TODO(), encryptKey)
	if err != nil {
		return "", nil, err
	}
	s.reporter.ReportRequest(context.TODO(), metrics.KMSEncryptOperationTypeValue, metrics.SuccessStatusTypeValue, time.Since(start).Seconds(), "")
	// Use base64 of encKey as the key into the cache because hashicorp/golang-lru
	// cannot hash []uint8.
	s.transformers.Add(base64.StdEncoding.EncodeToString(encryptedKEK), encryptKey)
	return base64.StdEncoding.EncodeToString(encryptedKEK), encryptKey, nil
}
