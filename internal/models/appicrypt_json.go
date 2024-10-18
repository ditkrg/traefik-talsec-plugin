package models

import "strconv"

type AppiCryptJson struct {
	HeaderName           string                   `json:"headerName"`
	DecryptionKeys       map[string]string        `json:"decryptionKeys"`
	AllowedKeys          map[string]string        `json:"allowedKeys"`
	OccurrenceThreshold  string                   `json:"occurrenceThreshold,omitempty"`
	SecurityThreshold    string                   `json:"securityThreshold"`
	CheckConfiguration   CheckConfigurationJson   `json:"checkConfiguration"`
	AppInfoConfiguration AppInfoConfigurationJson `json:"appInfoConfiguration"`
}

type CheckConfigurationJson struct {
	PrivilegedAccess  struct{ CheckConfigurationPropJson } `json:"privilegedAccess"`
	UnofficialStore   struct{ CheckConfigurationPropJson } `json:"unofficialStore"`
	Debug             struct{ CheckConfigurationPropJson } `json:"debug"`
	Simulator         struct{ CheckConfigurationPropJson } `json:"simulator"`
	Overlay           struct{ CheckConfigurationPropJson } `json:"overlay"`
	Accessibility     struct{ CheckConfigurationPropJson } `json:"accessibility"`
	AppIntegrity      struct{ CheckConfigurationPropJson } `json:"appIntegrity"`
	Hooks             struct{ CheckConfigurationPropJson } `json:"hooks"`
	DeviceBinding     struct{ CheckConfigurationPropJson } `json:"deviceBinding"`
	ObfuscationIssues struct{ CheckConfigurationPropJson } `json:"obfuscationIssues"`
}

type CheckConfigurationPropJson struct {
	Weight string `env:"WEIGHT,default=100" json:"weight"`
}

type AppInfoConfigurationJson struct {
	Android AndroidJson `json:"android"`
	Ios     IosJson     `json:"ios"`
}

type AndroidJson struct {
	PackageNames             []string `json:"packageNames"`
	SigningCertificateHashes []string `json:"signingCertificateHashes"`
	AppVersion               string   `json:"appVersion"`
}

type IosJson struct {
	TeamID              string   `json:"teamId"`
	TeamIDFromMagicFile string   `json:"teamIDFromMagicFile"`
	Bundle              []string `json:"bundle"`
	IgnoreOnSimulator   string   `json:"ignoreOnSimulator"`
	AppVersion          string   `json:"appVersion"`
}

func (appiCryptJson *AppiCryptJson) ValidateAndConvertToConfig() (*AppiCryptConfig, error) {

	var err error

	appiCryptConfig := AppiCryptConfig{
		DecryptionKeys: appiCryptJson.DecryptionKeys,
		AllowedKeys:    appiCryptJson.AllowedKeys,
		HeaderName:     appiCryptJson.HeaderName,

		CheckConfiguration: CheckConfiguration{
			PrivilegedAccess:  CheckConfigurationProp{Weight: -1},
			UnofficialStore:   CheckConfigurationProp{Weight: -1},
			Debug:             CheckConfigurationProp{Weight: -1},
			Simulator:         CheckConfigurationProp{Weight: -1},
			Overlay:           CheckConfigurationProp{Weight: -1},
			Accessibility:     CheckConfigurationProp{Weight: -1},
			AppIntegrity:      CheckConfigurationProp{Weight: -1},
			Hooks:             CheckConfigurationProp{Weight: -1},
			DeviceBinding:     CheckConfigurationProp{Weight: -1},
			ObfuscationIssues: CheckConfigurationProp{Weight: -1},
		},
		AppInfoConfiguration: AppInfoConfiguration{
			Android: Android{
				PackageNames:             appiCryptJson.AppInfoConfiguration.Android.PackageNames,
				SigningCertificateHashes: appiCryptJson.AppInfoConfiguration.Android.SigningCertificateHashes,
				AppVersion:               appiCryptJson.AppInfoConfiguration.Android.AppVersion,
			},
			Ios: Ios{
				TeamID:              appiCryptJson.AppInfoConfiguration.Ios.TeamID,
				TeamIDFromMagicFile: appiCryptJson.AppInfoConfiguration.Ios.TeamIDFromMagicFile,
				Bundle:              appiCryptJson.AppInfoConfiguration.Ios.Bundle,
				AppVersion:          appiCryptJson.AppInfoConfiguration.Ios.AppVersion,
			},
		},
	}

	if appiCryptJson.OccurrenceThreshold != "" {

		if appiCryptConfig.OccurrenceThreshold, err = strconv.Atoi(appiCryptJson.OccurrenceThreshold); err != nil {
			return nil, err
		}
	}

	if appiCryptConfig.SecurityThreshold, err = strconv.Atoi(appiCryptJson.SecurityThreshold); err != nil {
		return nil, err
	}

	if appiCryptConfig.CheckConfiguration.PrivilegedAccess.Weight, err = strconv.Atoi(appiCryptJson.CheckConfiguration.PrivilegedAccess.Weight); err != nil {
		return nil, err
	}
	if appiCryptConfig.CheckConfiguration.UnofficialStore.Weight, err = strconv.Atoi(appiCryptJson.CheckConfiguration.UnofficialStore.Weight); err != nil {
		return nil, err
	}
	if appiCryptConfig.CheckConfiguration.Debug.Weight, err = strconv.Atoi(appiCryptJson.CheckConfiguration.Debug.Weight); err != nil {
		return nil, err
	}
	if appiCryptConfig.CheckConfiguration.Simulator.Weight, err = strconv.Atoi(appiCryptJson.CheckConfiguration.Simulator.Weight); err != nil {
		return nil, err
	}
	if appiCryptConfig.CheckConfiguration.Overlay.Weight, err = strconv.Atoi(appiCryptJson.CheckConfiguration.Overlay.Weight); err != nil {
		return nil, err
	}
	if appiCryptConfig.CheckConfiguration.Accessibility.Weight, err = strconv.Atoi(appiCryptJson.CheckConfiguration.Accessibility.Weight); err != nil {
		return nil, err
	}
	if appiCryptConfig.CheckConfiguration.AppIntegrity.Weight, err = strconv.Atoi(appiCryptJson.CheckConfiguration.AppIntegrity.Weight); err != nil {
		return nil, err
	}
	if appiCryptConfig.CheckConfiguration.Hooks.Weight, err = strconv.Atoi(appiCryptJson.CheckConfiguration.Hooks.Weight); err != nil {
		return nil, err
	}
	if appiCryptConfig.CheckConfiguration.DeviceBinding.Weight, err = strconv.Atoi(appiCryptJson.CheckConfiguration.DeviceBinding.Weight); err != nil {
		return nil, err
	}
	if appiCryptConfig.CheckConfiguration.ObfuscationIssues.Weight, err = strconv.Atoi(appiCryptJson.CheckConfiguration.ObfuscationIssues.Weight); err != nil {
		return nil, err
	}

	if appiCryptConfig.AppInfoConfiguration.Ios.IgnoreOnSimulator, err = strconv.ParseBool(appiCryptJson.AppInfoConfiguration.Ios.IgnoreOnSimulator); err != nil {
		return nil, err
	}

	return &appiCryptConfig, nil
}
