package mfa

import (
	"2fatvalidate/api/utils"
	"encoding/base32"
	"fmt"
	"math/rand"
	"os"
	"strings"

	"github.com/dgryski/dgoogauth"
	"github.com/pkg/errors"
	"rsc.io/qr"
)

type MFA struct {
	otpConfig *dgoogauth.OTPConfig
}

func NewMFA(secret string) *MFA {
	otpConfig := &dgoogauth.OTPConfig{
		Secret:     secret,
		WindowSize: 3,
	}
	return &MFA{otpConfig}
}

func newRandomBase32String(size int) string {
	data := make([]byte, size)
	rand.Read(data)
	return base32.StdEncoding.EncodeToString(data)
}

func generateQRCode(authLink string) error {
	code, err := qr.Encode(authLink, qr.M)
	if err != nil {
		return err
	}
	return os.WriteFile("qrcode.png", code.PNG(), 0644)
}

func GetToken(user utils.User) error {
	secret := newRandomBase32String(20)

	issuer := "UserToken"
	userEmail := user.Name
	authLink := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s", issuer, userEmail, secret, issuer)

	err := generateQRCode(authLink)
	if err != nil {
		fmt.Println("Error generating QR code:", err)
		return err
	}

	fmt.Printf("Scan the QR code in %s into your MFA app (e.g., Google Authenticator)\n", "qrcode.png")

	mfa := NewMFA(secret)

	var token string
	fmt.Print("Enter the token from the app: ")
	fmt.Scanln(&token)

	valid, err := mfa.ValidateToken(token)
	if err != nil {
		fmt.Println("Error validating token:", err)
		return err
	}

	if valid {
		fmt.Println("Token is valid. MFA setup is successful!")
	} else {
		fmt.Println("Token is not valid. MFA setup failed.")
	}

	return nil
}

func (m *MFA) ValidateToken(token string) (bool, error) {
	trimmedToken := strings.TrimSpace(token)
	ok, err := m.otpConfig.Authenticate(trimmedToken)
	if err != nil {
		return false, errors.Wrap(err, "unable to parse the token")
	}
	return ok, nil
}
