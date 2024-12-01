package services

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/ditkrg/traefik-talsec-plugin/internal/models"
	"github.com/golang-jwt/jwt/v5"
)

type AppiCryptService struct {
	Configs *models.AppiCryptConfig
}

func NewAppiCryptService(configs *models.AppiCryptConfig) *AppiCryptService {
	return &AppiCryptService{
		Configs: configs,
	}
}

func (a *AppiCryptService) HandleRequest(req *http.Request) error {
	claims, err := a.DecodeJwtAndVerify(req.Header)
	if err != nil {
		return err
	}

	expectedNonce, err := a.GenerateNonce(req)
	if err != nil {
		return err
	}

	nonce, deviceData, err := a.DecryptCryptogram(claims)
	if err != nil {
		return err
	}

	if err := a.ValidateCryptogram(expectedNonce, nonce, deviceData); err != nil {
		return err
	}

	return nil
}

func (a *AppiCryptService) GenerateNonce(req *http.Request) ([]byte, error) {
	date := req.Header.Get(a.Configs.DateHeaderKey)

	if date == "" {
		return nil, fmt.Errorf("no date data found in request headers, looking for key %s", a.Configs.DateHeaderKey)
	}

	nonce := fmt.Sprintf("%s,%s,%s", date, req.Method, req.URL.Path)

	if req.Method == http.MethodGet || req.Method == http.MethodDelete || req.Body == http.NoBody {
		return []byte(nonce), nil
	}

	var bodyCopy bytes.Buffer
	tee := io.TeeReader(req.Body, &bodyCopy)

	hasher := sha256.New()
	if _, err := io.Copy(hasher, tee); err != nil {
		return nil, err
	}

	req.Body = io.NopCloser(&bodyCopy)

	if bodyCopy.Len() == 0 {
		return []byte(nonce), nil
	}

	hash := hasher.Sum(nil)

	nonce = fmt.Sprintf("%s,%s", nonce, hex.EncodeToString(hash))

	return []byte(nonce), nil
}

func (a *AppiCryptService) DecodeJwtAndVerify(headers http.Header) (jwt.MapClaims, error) {
	appiCrypt := headers.Get(a.Configs.AppiCryptHeaderName)

	if appiCrypt == "" {
		return nil, fmt.Errorf("no encrypted data found in request headers, looking for key %s", a.Configs.AppiCryptHeaderName)
	}

	claims := jwt.MapClaims{}

	_, err := jwt.ParseWithClaims(appiCrypt, claims, func(token *jwt.Token) (interface{}, error) {
		kid := token.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("kid is empty")
		}

		publicKey := a.Configs.GetAllowedKeys()[kid]
		if publicKey == nil {
			return nil, fmt.Errorf("public key not found for kid %s", kid)
		}

		return publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	return claims, nil
}

func (a *AppiCryptService) DecryptCryptogram(claims jwt.MapClaims) ([]byte, *models.DeviceData, error) {

	cryptogram, err := getCryptogram(claims)
	if err != nil {
		return nil, nil, err
	}

	var decryptionKey []byte

	versionClaim := claims["version"]

	if versionClaim == nil {
		decryptionKey = a.Configs.GetDecryptionKeys()["legacyKey"]
	} else if versionClaim.(float64) == 2 {

		kidClaim := claims["kid"]
		if kidClaim == nil {
			return nil, nil, errors.New("JWS payload doesn't contain KID")
		}

		kid := kidClaim.(string)
		if kid == "" {
			return nil, nil, errors.New("JWS payload doesn't contain KID")
		}

		decryptionKey = a.Configs.GetDecryptionKeys()[kid]
	}

	if decryptionKey == nil {
		return nil, nil, errors.New("no private key found for decryption")
	}

	bitKeySize, err := getBitKeySize(decryptionKey)
	if err != nil {
		return nil, nil, err
	}

	encryptedData := cryptogram[len(cryptogram)-bitKeySize:]
	encryptedDeviceData := cryptogram[:len(cryptogram)-bitKeySize]

	decryptedData, err := decryptData(encryptedData, decryptionKey)
	if err != nil {
		return nil, nil, err
	}

	iv := decryptedData[:16]
	aesKey := decryptedData[16:32]
	nonce := decryptedData[32:]

	decryptedDeviceData, err := decryptDeviceData(encryptedDeviceData, aesKey, iv)
	if err != nil {
		return nil, nil, err
	}

	return nonce, decryptedDeviceData, nil
}

func getCryptogram(claims jwt.MapClaims) ([]byte, error) {
	cryptogramClaim := claims["cryptogram"]
	if cryptogramClaim == nil {
		return nil, errors.New("JWS payload doesn't contain cryptogram")
	}

	cryptogram := cryptogramClaim.(string)
	if cryptogram == "" {
		return nil, errors.New("JWS payload doesn't contain cryptogram")
	}

	cryptogram = strings.ReplaceAll(cryptogram, "_", "/")
	cryptogram = strings.ReplaceAll(cryptogram, "-", "+")

	// Add padding if necessary
	switch len(cryptogram) % 4 {
	case 2:
		cryptogram += "=="
	case 3:
		cryptogram += "="
	}

	return base64.StdEncoding.DecodeString(cryptogram)
}

func decryptData(data []byte, privateKey []byte) ([]byte, error) {
	privKey, err := x509.ParsePKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	rsaPrivKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}

	// Decrypt data
	result, err := rsa.DecryptOAEP(sha1.New(), nil, rsaPrivKey, data, nil)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func decryptDeviceData(payload []byte, symmetricKey []byte, iv []byte) (*models.DeviceData, error) {
	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, err
	}

	if len(iv) != aes.BlockSize {
		return nil, errors.New("invalid IV size")
	}

	if len(payload)%aes.BlockSize != 0 {
		return nil, errors.New("invalid payload size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(payload))
	mode.CryptBlocks(decrypted, payload)

	// Unpadding (assuming PKCS7 padding)
	decrypted, err = pkcs7Unpad(decrypted, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	// Parse JSON into a map
	var deviceData models.DeviceData
	if err := json.Unmarshal(decrypted, &deviceData); err != nil {
		return nil, err
	}

	return &deviceData, nil
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 || length%blockSize != 0 {
		return nil, errors.New("invalid data for PKCS7 unpadding")
	}

	paddingLen := int(data[length-1])
	if paddingLen == 0 || paddingLen > blockSize {
		return nil, errors.New("invalid padding length")
	}

	for _, v := range data[length-paddingLen:] {
		if int(v) != paddingLen {
			return nil, errors.New("invalid padding")
		}
	}

	return data[:length-paddingLen], nil
}

func getBitKeySize(bytes []byte) (int, error) {

	offset := 33 + 1 + 1
	if len(bytes) <= offset+1 {
		return 0, errors.New("invalid byte array length")
	}

	result := (int(bytes[offset])*256 + int(bytes[offset+1]) - 1) * 8

	for _, size := range []int{2048, 3072, 4096} {
		if result == size {
			return result / 8, nil
		}
	}

	return 0, fmt.Errorf("invalid key size %d", result)
}

func (a *AppiCryptService) ValidateCryptogram(expectedNonce []byte, nonce []byte, deviceData *models.DeviceData) error {

	if err := a.checkNonce(expectedNonce, nonce); err != nil {
		return err
	}

	if err := a.checkLicensing(deviceData); err != nil {
		return err
	}

	if err := a.checkMaxAge(deviceData); err != nil {
		return err
	}

	if err := a.containsAllCriticalChecks(deviceData); err != nil {
		return err
	}

	if err := a.checkAppInfoAndroid(deviceData); err != nil {
		return err
	}

	if err := a.checkAppInfoIOs(deviceData); err != nil {
		return err
	}

	if err := a.checkRiskScore(deviceData); err != nil {
		return err
	}

	return nil
}

func (a *AppiCryptService) checkLicensing(deviceData *models.DeviceData) error {
	if deviceData.Licensing.EndOfGracePeriod == 0 {
		return nil
	}

	timeNowUnixMilli := time.Now().UnixMilli()
	if timeNowUnixMilli > deviceData.Licensing.EndOfGracePeriod {
		return fmt.Errorf("end of grace period reached, server time is ahead of device time, %d > %d", timeNowUnixMilli, deviceData.Licensing.EndOfGracePeriod)
	}

	return nil
}

func (a *AppiCryptService) checkMaxAge(deviceData *models.DeviceData) error {
	occurrenceThreshold := a.Configs.OccurrenceThreshold

	if occurrenceThreshold == 0 {
		return nil
	}

	deviceOccurrence, err := time.Parse("2006-01-02T15:04:05.000000-0700", deviceData.Occurrence)
	if err != nil {
		return err
	}

	difference := time.Since(deviceOccurrence)
	differenceInSeconds := int(difference.Seconds())

	if differenceInSeconds > occurrenceThreshold {
		return fmt.Errorf("occurrence difference is bigger than threshold, seconds since request sent: %d, threshold: %d", differenceInSeconds, occurrenceThreshold)
	} else if differenceInSeconds < -60 {
		return fmt.Errorf("occurrence timestamp is in the future, seconds since request sent: %d", differenceInSeconds)
	}

	return nil
}

func (a *AppiCryptService) containsAllCriticalChecks(deviceData *models.DeviceData) error {

	if deviceData.Checks.PrivilegedAccess == nil {
		return errors.New("device data missing one of critical checks: privilegedAccess")
	}

	if deviceData.Checks.AppIntegrity == nil {
		return errors.New("device data missing one of critical checks: appIntegrity")
	}

	if deviceData.Checks.Debug == nil {
		return errors.New("device data missing one of critical checks: debug")
	}

	if deviceData.Checks.UnofficialStore == nil {
		return errors.New("device data missing one of critical checks: unofficialStore")
	}

	return nil
}

func (a *AppiCryptService) checkAppInfoAndroid(deviceData *models.DeviceData) error {
	if deviceData.Platform != "Android" {
		return nil
	}

	appInfoConfig := a.Configs.AppInfoConfiguration.Android
	packageName := deviceData.AppInfo.PackageName

	if !contains(appInfoConfig.PackageNames, packageName) {
		return fmt.Errorf("android: invalid package name, expected one of %v, got %s", appInfoConfig.PackageNames, packageName)
	}

	if !contains(appInfoConfig.SigningCertificateHashes, deviceData.AppInfo.SigningCertificateHash) {
		return fmt.Errorf("android: invalid signing certificate hash, expected one of %v, got %s", appInfoConfig.SigningCertificateHashes, deviceData.AppInfo.SigningCertificateHash)
	}

	return nil
}

func (a *AppiCryptService) checkAppInfoIOs(deviceData *models.DeviceData) error {
	if deviceData.Platform != "iOS" {
		return nil
	}

	if deviceData.Checks.Simulator.Status == "NOK" && a.Configs.AppInfoConfiguration.Ios.IgnoreOnSimulator {
		return nil
	}

	appInfoConfig := a.Configs.AppInfoConfiguration.Ios
	appInfo := deviceData.AppInfo

	teamId := appInfo.TeamID

	if teamId == "" {
		teamId = appInfo.TeamIDFromMagicFile
	}

	if teamId == "" {
		return fmt.Errorf("IOS: missing team ID")
	}

	if teamId != appInfoConfig.TeamID {
		return fmt.Errorf("IOS: invalid team ID, expected %s, got %s", appInfoConfig.TeamID, teamId)
	}

	if !contains(appInfoConfig.Bundle, appInfo.Bundle) {
		return fmt.Errorf("IOS: invalid bundle, expected one of %v, got %s", appInfoConfig.Bundle, appInfo.Bundle)
	}

	return nil
}

func (a *AppiCryptService) checkRiskScore(deviceData *models.DeviceData) error {

	riskScore := 0

	if deviceData.Checks.Accessibility != nil && deviceData.Checks.Accessibility.Status != "OK" {
		riskScore += a.Configs.CheckConfiguration.Accessibility.Weight
	}

	if deviceData.Checks.ObfuscationIssues != nil && deviceData.Checks.ObfuscationIssues.Status != "OK" {
		riskScore += a.Configs.CheckConfiguration.ObfuscationIssues.Weight
	}

	if deviceData.Checks.UnofficialStore != nil && deviceData.Checks.UnofficialStore.Status != "OK" {
		riskScore += a.Configs.CheckConfiguration.UnofficialStore.Weight
	}

	if deviceData.Checks.Debug != nil && deviceData.Checks.Debug.Status != "OK" {
		riskScore += a.Configs.CheckConfiguration.Debug.Weight
	}

	if deviceData.Checks.Simulator != nil && deviceData.Checks.Simulator.Status != "OK" {
		riskScore += a.Configs.CheckConfiguration.Simulator.Weight
	}

	if deviceData.Checks.PrivilegedAccess != nil && deviceData.Checks.PrivilegedAccess.Status != "OK" {
		riskScore += a.Configs.CheckConfiguration.PrivilegedAccess.Weight
	}

	if deviceData.Checks.AppIntegrity != nil && deviceData.Checks.AppIntegrity.Status != "OK" {
		riskScore += a.Configs.CheckConfiguration.AppIntegrity.Weight
	}

	if deviceData.Checks.Hooks != nil && deviceData.Checks.Hooks.Status != "OK" {
		riskScore += a.Configs.CheckConfiguration.Hooks.Weight
	}

	if deviceData.Checks.DeviceBinding != nil && deviceData.Checks.DeviceBinding.Status != "OK" {
		riskScore += a.Configs.CheckConfiguration.DeviceBinding.Weight
	}

	if riskScore >= a.Configs.SecurityThreshold {
		return fmt.Errorf("risk score is too high, allowed risk score of %d and lower, got %d", a.Configs.SecurityThreshold, riskScore)
	}

	return nil
}

func (a *AppiCryptService) checkNonce(expectedNonce []byte, nonce []byte) error {
	if len(expectedNonce) != len(nonce) {
		return errors.New("expected nonce and request nonce do not match in length")
	}

	if !reflect.DeepEqual(expectedNonce, nonce) {
		return errors.New("expected nonce and request nonce do not match")
	}

	return nil
}

func contains(slice []string, value string) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}
