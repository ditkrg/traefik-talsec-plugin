package models

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
