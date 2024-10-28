package models

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
)

type AppiCryptConfig struct {
	DecryptionKeys      map[string]string
	AllowedKeys         map[string]string
	AppiCryptHeaderName string
	DateHeaderKey       string

	CheckConfiguration   CheckConfiguration
	AppInfoConfiguration AppInfoConfiguration

	OccurrenceThreshold int
	SecurityThreshold   int

	allowedKeys    map[string]any
	decryptionKeys map[string][]byte
}

type CheckConfiguration struct {
	PrivilegedAccess  CheckConfigurationProp
	UnofficialStore   CheckConfigurationProp
	Debug             CheckConfigurationProp
	Simulator         CheckConfigurationProp
	Overlay           CheckConfigurationProp
	Accessibility     CheckConfigurationProp
	AppIntegrity      CheckConfigurationProp
	Hooks             CheckConfigurationProp
	DeviceBinding     CheckConfigurationProp
	ObfuscationIssues CheckConfigurationProp
}

type CheckConfigurationProp struct {
	Weight int
}

type AppInfoConfiguration struct {
	Android Android
	Ios     Ios
}

type Android struct {
	PackageNames             []string
	SigningCertificateHashes []string
	AppVersion               string
}

type Ios struct {
	TeamID              string
	TeamIDFromMagicFile string
	Bundle              []string
	IgnoreOnSimulator   bool
	AppVersion          string
}

func (c *AppiCryptConfig) Validate() error {

	// ========================
	//	Validate the AppiCrypt configurations
	// ========================

	if msgs := validateAppiCryptConfigurations(c); len(msgs) != 0 {
		return fmt.Errorf("invalid configuration:\n  %s", strings.Join(msgs, "\n  "))
	}
	// ========================
	//	Prepare the allowed keys
	// ========================
	if err := prepareAllowedKeys(c); err != nil {
		return err
	}

	// ========================
	//	Prepare the decryption keys
	// ========================
	if err := prepareDecryptionKeys(c); err != nil {
		return err
	}

	return nil
}

func validateAppiCryptConfigurations(c *AppiCryptConfig) []string {
	msgs := []string{}

	if c.AppiCryptHeaderName == "" {
		msgs = append(msgs, "error: appiCrypt header name cannot be empty")
	}

	if c.DateHeaderKey == "" {
		msgs = append(msgs, "error: Date header name cannot be empty")
	}

	if c.OccurrenceThreshold < 0 {
		msgs = append(msgs, "error: OccurrenceThreshold cannot be negative")
	}

	if len(c.AllowedKeys) == 0 {
		msgs = append(msgs, "error: allowed keys cannot be empty")
	}

	if c.SecurityThreshold < 0 {
		msgs = append(msgs, "error: SecurityThreshold cannot be negative")
	}

	if c.CheckConfiguration.PrivilegedAccess.Weight < 0 {
		msgs = append(msgs, "error: PrivilegedAccess weight cannot be negative")
	}

	if c.CheckConfiguration.UnofficialStore.Weight < 0 {
		msgs = append(msgs, "error: UnofficialStore weight cannot be negative")
	}

	if c.CheckConfiguration.Debug.Weight < 0 {
		msgs = append(msgs, "error: Debug weight cannot be negative")
	}

	if c.CheckConfiguration.Simulator.Weight < 0 {
		msgs = append(msgs, "error: Simulator weight cannot be negative")
	}

	if c.CheckConfiguration.Overlay.Weight < 0 {
		msgs = append(msgs, "error: overlay weight cannot be negative")
	}

	if c.CheckConfiguration.Accessibility.Weight < 0 {
		msgs = append(msgs, "error: Accessibility weight cannot be negative")
	}

	if c.CheckConfiguration.AppIntegrity.Weight < 0 {
		msgs = append(msgs, "error: AppIntegrity weight cannot be negative")
	}

	if c.CheckConfiguration.Hooks.Weight < 0 {
		msgs = append(msgs, "error: hooks weight cannot be negative")
	}

	if c.CheckConfiguration.DeviceBinding.Weight < 0 {
		msgs = append(msgs, "error: device binding cannot be negative")
	}

	if c.CheckConfiguration.ObfuscationIssues.Weight < 0 {
		msgs = append(msgs, "error: ObfuscationIssues weight cannot be negative")
	}

	if len(c.AppInfoConfiguration.Android.PackageNames) <= 0 {
		msgs = append(msgs, "error: android package names cannot be empty")
	}

	if c.AppInfoConfiguration.Ios.TeamID == "" {
		msgs = append(msgs, "error: ios team id cannot be empty")
	}

	if len(c.AppInfoConfiguration.Ios.Bundle) <= 0 {
		msgs = append(msgs, "error: ios bundle cannot be empty")
	}

	return msgs
}

func prepareAllowedKeys(c *AppiCryptConfig) error {
	c.allowedKeys = make(map[string]any)

	for key, certificate := range c.AllowedKeys {

		block, _ := pem.Decode([]byte(certificate))
		if block == nil || block.Type != "CERTIFICATE" {
			return fmt.Errorf("failed to decode PEM block containing certificate")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %v", err)
		}

		c.allowedKeys[key] = cert.PublicKey
	}

	return nil
}

func prepareDecryptionKeys(c *AppiCryptConfig) error {
	c.decryptionKeys = make(map[string][]byte)

	for key, decryptionKey := range c.DecryptionKeys {

		decodedKey, err := base64.StdEncoding.DecodeString(decryptionKey)
		if err != nil {
			return err
		}

		c.decryptionKeys[key] = decodedKey
	}

	return nil
}

func (c *AppiCryptConfig) GetAllowedKeys() map[string]any {
	return c.allowedKeys
}

func (c *AppiCryptConfig) GetDecryptionKeys() map[string][]byte {
	return c.decryptionKeys
}
