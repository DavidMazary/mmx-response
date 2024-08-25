package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

const (
	challengeFile = "mmx_challenge.txt"
	responseFile  = "mmx_response.txt"
)

type mmxChallenge struct {
	algorithmType   []byte
	randomChallenge []byte
	softwareVersion []byte
	chipID          []byte
	fazit           []byte

	size int
}

func loadChallenge(challengeFile string) (*mmxChallenge, error) {
	hexEncodedChallenge, err := os.ReadFile(challengeFile)
	if err != nil {
		slog.Error("Failed to decode file as hex",
			"error", err,
			"challengeFile", challengeFile,
		)
		return nil, err
	}

	hexEncodedChallenge = bytes.TrimSpace(hexEncodedChallenge)

	challengeSize := len(hexEncodedChallenge)

	challengeData := make([]byte, challengeSize*2)

	_, err = hex.Decode(challengeData, hexEncodedChallenge)
	if err != nil {
		slog.Error("Failed to hex decode data from challenge file",
			"error", err,
			"challengeData", challengeData,
			"challengeFile", challengeFile,
		)
		return nil, err
	}

	parts := bytes.Split(challengeData, []byte{10})

	challenge := mmxChallenge{
		algorithmType:   parts[0],
		randomChallenge: parts[1],
		softwareVersion: parts[2],
		chipID:          parts[3],
		fazit:           parts[4],
		size:            challengeSize,
	}

	slog.Info("Parsed challenge",
		"algorithmType", challenge.algorithmType,
		"randomChallenge", challenge.randomChallenge,
		"softwareVersion", challenge.softwareVersion,
		"chipID", challenge.chipID,
		"FAZIT", challenge.fazit,
	)

	return &challenge, nil
}

// sign constructs a payload from the challenge and signs the hashed payload.
func (c *mmxChallenge) sign() ([]byte, error) {
	dataToSign := make([]byte, 0, c.size*2)

	dataToSign = append(dataToSign, c.randomChallenge...)
	dataToSign = append(dataToSign, make([]byte, 0x13)...)
	dataToSign = append(dataToSign, c.chipID...)
	dataToSign = append(dataToSign, 10) // Line feed
	dataToSign = append(dataToSign, c.softwareVersion...)

	slog.Debug("Generated data to sign",
		"string", string(dataToSign),
		"binary", hex.EncodeToString(dataToSign),
	)

	signature, err := signData(dataToSign)
	if err != nil {
		slog.Error("Failed to sign response",
			"error", err,
		)
		return nil, err
	}

	return signature, nil
}

func main() {
	challenge, err := loadChallenge(challengeFile)
	if err != nil {
		slog.Error("Failed to load challenge from file",
			"error", err,
		)
		os.Exit(1)
	}

	signature, err := challenge.sign()
	if err != nil {
		slog.Error("Failed to sign challenge data",
			"error", err,
		)
		os.Exit(1)
	}

	const responsePad = 24
	const signatureLen = 384 // sha256

	responseLen := len(challenge.randomChallenge) + responsePad + signatureLen

	responseData := make([]byte, 0, responseLen)
	responseData = append(responseData, challenge.randomChallenge...)
	responseData = append(responseData, make([]byte, 24)...)
	responseData = append(responseData, signature...)

	responseString := make([]byte, responseLen*2)
	hex.Encode(responseString, responseData)

	responseFile, err := os.Create(responseFile)
	if err != nil {
		slog.Error("Failed to create response file",
			"error", err,
		)
		os.Exit(1)
	}
	defer responseFile.Close()

	fmt.Fprint(responseFile, strings.ToUpper(string(responseString)))

	slog.Info("Successfully generated response")
}

const key = `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`

func signData(message []byte) ([]byte, error) {
	privateKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		panic(fmt.Errorf("error base64 decoding private key: %w", err))
	}

	privKey, err := x509.ParsePKCS1PrivateKey(privateKey)
	if err != nil {
		panic(fmt.Errorf("error loading private key: %w", err))
	}

	messageHash := sha256.Sum256(message)

	slog.Debug("Hashed message",
		"hash", hex.EncodeToString(messageHash[:]),
	)

	signature, err := rsa.SignPKCS1v15(nil, privKey, crypto.SHA256, messageHash[:])
	if err != nil {
		return nil, fmt.Errorf("error signing message: %w", err)
	}

	slog.Debug("Signed response",
		"length", len(signature),
		"signature", hex.EncodeToString(signature),
	)

	return signature, nil
}
