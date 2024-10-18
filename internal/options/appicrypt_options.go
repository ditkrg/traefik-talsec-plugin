package options

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

type AppiCryptOptions struct {
	DecryptionKeys              map[string]string `json:"DECRYPTION_KEYS"`
	AppiCryptConfigurationsPath string            `json:"CONFIGURATION_PATH"`
	HeaderName                  string            `json:"HEADER_NAME,default=AppiCrypt"`

	appiCryptConfigurations *AppiCryptConfigurations
	allowedKeys             map[string]any
	decryptionKeys          map[string][]byte
}

type AppiCryptConfigurations struct {
	CheckConfiguration   CheckConfiguration   `json:"checkConfiguration"`
	AppInfoConfiguration AppInfoConfiguration `json:"appInfoConfiguration"`
	AllowedKeys          map[string]string    `json:"allowedKeys"`
	OccurrenceThreshold  int                  `json:"occurrenceThreshold"`
	SecurityThreshold    int                  `json:"securityThreshold"`
}

type CheckConfiguration struct {
	PrivilegedAccess  struct{ CheckConfigurationProp } `json:"privilegedAccess"`
	UnofficialStore   struct{ CheckConfigurationProp } `json:"unofficialStore"`
	Debug             struct{ CheckConfigurationProp } `json:"debug"`
	Simulator         struct{ CheckConfigurationProp } `json:"simulator"`
	Overlay           struct{ CheckConfigurationProp } `json:"overlay"`
	Accessibility     struct{ CheckConfigurationProp } `json:"accessibility"`
	AppIntegrity      struct{ CheckConfigurationProp } `json:"appIntegrity"`
	Hooks             struct{ CheckConfigurationProp } `json:"hooks"`
	DeviceBinding     struct{ CheckConfigurationProp } `json:"deviceBinding"`
	ObfuscationIssues struct{ CheckConfigurationProp } `json:"obfuscationIssues"`
}

type CheckConfigurationProp struct {
	Weight int `env:"WEIGHT,default=100" json:"weight"`
}

type AppInfoConfiguration struct {
	Android Android `json:"android"`
	Ios     Ios     `json:"ios"`
}

type Android struct {
	PackageNames             []string `json:"packageNames"`
	SigningCertificateHashes []string `json:"signingCertificateHashes"`
	AppVersion               string   `json:"appVersion"`
}

type Ios struct {
	TeamID              string   `json:"teamId"`
	TeamIDFromMagicFile string   `json:"teamIDFromMagicFile"`
	Bundle              []string `json:"bundle"`
	IgnoreOnSimulator   bool     `json:"ignoreOnSimulator"`
	AppVersion          string   `json:"appVersion"`
}

func (c *AppiCryptOptions) Validate() error {

	// ========================
	// Make sure the config file path is loaded
	// ========================
	if c.AppiCryptConfigurationsPath == "" {
		return errors.New("error: CONFIGURATION_PATH cannot be empty")
	}

	// ========================
	//	Parse the AppiCrypt configurations
	// ========================
	if err := parseAppiCryptConfigurations(c); err != nil {
		return err
	}

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

func validateAppiCryptConfigurations(c *AppiCryptOptions) []string {
	msgs := []string{}

	if c.appiCryptConfigurations.OccurrenceThreshold < 0 {
		msgs = append(msgs, "error: OccurrenceThreshold cannot be negative")
	}

	if len(c.appiCryptConfigurations.AllowedKeys) == 0 {
		msgs = append(msgs, "error: allowed keys cannot be empty")
	}

	if c.appiCryptConfigurations.SecurityThreshold < 0 {
		msgs = append(msgs, "error: SecurityThreshold cannot be negative")
	}

	if c.appiCryptConfigurations.CheckConfiguration.PrivilegedAccess.Weight < 0 {
		msgs = append(msgs, "error: PrivilegedAccess weight cannot be negative")
	}

	if c.appiCryptConfigurations.CheckConfiguration.UnofficialStore.Weight < 0 {
		msgs = append(msgs, "error: UnofficialStore weight cannot be negative")
	}

	if c.appiCryptConfigurations.CheckConfiguration.Debug.Weight < 0 {
		msgs = append(msgs, "error: Debug weight cannot be negative")
	}

	if c.appiCryptConfigurations.CheckConfiguration.Simulator.Weight < 0 {
		msgs = append(msgs, "error: Simulator weight cannot be negative")
	}

	if c.appiCryptConfigurations.CheckConfiguration.Overlay.Weight < 0 {
		msgs = append(msgs, "error: overlay weight cannot be negative")
	}

	if c.appiCryptConfigurations.CheckConfiguration.Accessibility.Weight < 0 {
		msgs = append(msgs, "error: Accessibility weight cannot be negative")
	}

	if c.appiCryptConfigurations.CheckConfiguration.AppIntegrity.Weight < 0 {
		msgs = append(msgs, "error: AppIntegrity weight cannot be negative")
	}

	if c.appiCryptConfigurations.CheckConfiguration.Hooks.Weight < 0 {
		msgs = append(msgs, "error: hooks weight cannot be negative")
	}

	if c.appiCryptConfigurations.CheckConfiguration.DeviceBinding.Weight < 0 {
		msgs = append(msgs, "error: device binding cannot be negative")
	}

	if c.appiCryptConfigurations.CheckConfiguration.ObfuscationIssues.Weight < 0 {
		msgs = append(msgs, "error: ObfuscationIssues weight cannot be negative")
	}

	if len(c.appiCryptConfigurations.AppInfoConfiguration.Android.PackageNames) <= 0 {
		msgs = append(msgs, "error: android package names cannot be empty")
	}

	if c.appiCryptConfigurations.AppInfoConfiguration.Ios.TeamID == "" {
		msgs = append(msgs, "error: ios team id cannot be empty")
	}

	if len(c.appiCryptConfigurations.AppInfoConfiguration.Ios.Bundle) <= 0 {
		msgs = append(msgs, "error: ios bundle cannot be empty")
	}

	return msgs
}

func parseAppiCryptConfigurations(c *AppiCryptOptions) error {
	file, err := os.Open(c.AppiCryptConfigurationsPath)

	if err != nil {
		return err
	}

	defer file.Close()

	var appiCryptConfigurations AppiCryptConfigurations
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&appiCryptConfigurations)
	if err != nil {
		return err
	}

	c.appiCryptConfigurations = &appiCryptConfigurations

	return nil
}

func prepareAllowedKeys(c *AppiCryptOptions) error {
	c.allowedKeys = make(map[string]any)

	for key, certificate := range c.appiCryptConfigurations.AllowedKeys {

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

func prepareDecryptionKeys(c *AppiCryptOptions) error {
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

func (c *AppiCryptOptions) GetAppiCryptConfigurations() *AppiCryptConfigurations {
	return c.appiCryptConfigurations
}

func (c *AppiCryptOptions) GetAllowedKeys() map[string]any {
	return c.allowedKeys
}

func (c *AppiCryptOptions) GetDecryptionKeys() map[string][]byte {
	return c.decryptionKeys
}

// ===============================
// Device Data
// ===============================

type DeviceData struct {
	LoggingSslPinning bool         `json:"loggingSslPinning"`
	Occurrence        string       `json:"occurence"`
	InstanceId        string       `json:"instanceId"`
	SdkVersion        string       `json:"sdkVersion"`
	Platform          string       `json:"platform"`
	SdkPlatform       string       `json:"sdkPlatform"`
	AppInfo           *AppInfo     `json:"appInfo"`
	DeviceInfo        *DeviceInfo  `json:"deviceInfo"`
	DeviceId          *DeviceId    `json:"deviceId"`
	DeviceState       *DeviceState `json:"deviceState"`
	Checks            *Checks      `json:"checks"`
	Licensing         *Licensing   `json:"licensing"`
}

type AppInfo struct {
	TeamID                 string `json:"teamId"`
	TeamIDFromMagicFile    string `json:"teamIdFromMagicFile"`
	IgnoreOnSimulator      bool   `json:"ignoreOnSimulator"`
	AppVersion             string `json:"appVersion"`
	Bundle                 string `json:"bundle"`
	PackageName            string `json:"packageName"`
	SigningCertificateHash string `json:"signingCertificateHash"`
}

type DeviceInfo struct {
	OsVersion    string `json:"osVersion"`
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
}

type DeviceId struct {
	AndroidId       string `json:"androidId"`
	MediaDrm        string `json:"mediaDrm"`
	FingerprintV3   string `json:"fingerprintV3"`
	CurrentVendorId string `json:"currentVendorId"`
}

type DeviceState struct {
	Security                string             `json:"security"`
	Biometrics              string             `json:"biometrics"`
	HwBackedKeychain        string             `json:"hwBackedKeychain"`
	IsAdbEnabled            string             `json:"isAdbEnabled"`
	HasGoogleMobileServices bool               `json:"hasGoogleMobileServices"`
	HasHuaweiMobileServices bool               `json:"hasHuaweiMobileServices"`
	SelinuxProperties       *SelinuxProperties `json:"selinuxProperties"`
	SecurityPatch           string             `json:"securityPatch"`
}

type SelinuxProperties struct {
	BuildSelinuxProperty          string `json:"buildSelinuxProperty"`
	SelinuxMode                   string `json:"selinuxMode"`
	BootSelinuxProperty           string `json:"bootSelinuxProperty"`
	SelinuxEnforcementFileContent string `json:"selinuxEnforcementFileContent"`
	SelinuxEnabledReflect         string `json:"selinuxEnabledReflect"`
	SelinuxEnforcedReflect        string `json:"selinuxEnforcedReflect"`
}

type Licensing struct {
	EndOfGracePeriod int64 `json:"endOfGracePeriod"`
	LocallyExpired   bool  `json:"locallyExpired"`
}

type Checks struct {
	Accessibility     *ChecksStatus `json:"accessibility"`
	ObfuscationIssues *ChecksStatus `json:"obfuscationIssues"`
	UnofficialStore   *ChecksStatus `json:"unofficialStore"`
	Debug             *ChecksStatus `json:"debug"`
	Simulator         *ChecksStatus `json:"simulator"`
	PrivilegedAccess  *ChecksStatus `json:"privilegedAccess"`
	AppIntegrity      *ChecksStatus `json:"appIntegrity"`
	Hooks             *ChecksStatus `json:"hooks"`
	DeviceBinding     *ChecksStatus `json:"deviceBinding"`
}

type ChecksStatus struct {
	Status string  `json:"status"`
	TimeMs float64 `json:"timeMs"`
}
