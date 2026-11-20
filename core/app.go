package core

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/pem"
	"fmt"
	"github.com/vrischmann/userdir"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"res-downloader/core/shared"
	"strconv"
	"time"
)

type App struct {
	ctx         context.Context
	assets      embed.FS
	AppName     string `json:"AppName"`
	Version     string `json:"Version"`
	Description string `json:"Description"`
	Copyright   string `json:"Copyright"`
	UserDir     string `json:"-"`
	LockFile    string `json:"-"`
	PublicCrt   []byte `json:"-"`
	PrivateKey  []byte `json:"-"`
	IsProxy     bool   `json:"IsProxy"`
	IsReset     bool   `json:"-"`
}

var (
	appOnce        *App
	globalConfig   *Config
	globalLogger   *Logger
	resourceOnce   *Resource
	systemOnce     *SystemSetup
	proxyOnce      *Proxy
	httpServerOnce *HttpServer
	ruleOnce       *RuleSet
)

func GetApp(assets embed.FS, wjs string) *App {
	if appOnce == nil {
		matches := regexp.MustCompile(`"productVersion":\s*"([\d.]+)"`).FindStringSubmatch(wjs)
		version := "1.0.1"
		if len(matches) > 0 {
			version = matches[1]
		}

		appOnce = &App{
			assets:      assets,
			AppName:     "res-downloader",
			Version:     version,
			Description: "res-downloader是一款集网络资源嗅探 + 高速下载功能于一体的软件，高颜值、高性能和多样化，提供个人用户下载自己上传到各大平台的网络资源功能！",
			Copyright:   "Copyright © 2023~" + strconv.Itoa(time.Now().Year()),
			IsReset:     false,
		}
		appOnce.UserDir = filepath.Join(userdir.GetConfigHome(), appOnce.AppName)
		err := os.MkdirAll(appOnce.UserDir, 0750)
		if err != nil {
			fmt.Println("Mkdir UserDir err: ", err.Error())
		}
		appOnce.LockFile = filepath.Join(appOnce.UserDir, "install.lock")
		appOnce.loadOrGenerateCert()
		initLogger()
		initConfig()
		initProxy()
		initResource()
		initHttpServer()
		initSystem()
		initRule()
	}
	return appOnce
}

func (a *App) Startup(ctx context.Context) {
	a.ctx = ctx
	go httpServerOnce.run()
}

func (a *App) OnExit() {
	a.UnsetSystemProxy()
	globalLogger.Close()
	if appOnce.IsReset {
		err := a.ResetApp()
		fmt.Println("err:", err)
	}
}

func (a *App) installCert() (string, error) {
	out, err := systemOnce.installCert()
	if err != nil {
		globalLogger.Esg(err, out)
		return out, err
	} else {
		if err := a.lock(); err != nil {
			globalLogger.Err(err)
		}
	}
	return out, nil
}

func (a *App) OpenSystemProxy() error {
	if a.IsProxy {
		return nil
	}
	err := systemOnce.setProxy()
	if err == nil {
		a.IsProxy = true
		return nil
	}
	return err
}

func (a *App) UnsetSystemProxy() error {
	if !a.IsProxy {
		return nil
	}
	err := systemOnce.unsetProxy()
	if err == nil {
		a.IsProxy = false
		return nil
	}
	return err
}

func (a *App) isInstall() bool {
	return shared.FileExist(a.LockFile)
}

func (a *App) lock() error {
	err := os.WriteFile(a.LockFile, []byte("success"), 0644)
	if err != nil {
		return err
	}
	return nil
}

func (a *App) ResetApp() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return err
	}

	_ = os.Remove(filepath.Join(appOnce.UserDir, "install.lock"))
	_ = os.Remove(filepath.Join(appOnce.UserDir, "pass.cache"))
	_ = os.Remove(filepath.Join(appOnce.UserDir, "config.json"))
	_ = os.Remove(filepath.Join(appOnce.UserDir, "cert.crt"))
	_ = os.Remove(filepath.Join(appOnce.UserDir, "cert.key"))

	cmd := exec.Command(exePath)
	cmd.Start()
	return nil
}

func (a *App) loadOrGenerateCert() {
	certFile := filepath.Join(a.UserDir, "cert.crt")
	keyFile := filepath.Join(a.UserDir, "cert.key")

	if certData, err := os.ReadFile(certFile); err == nil {
		if keyData, err := os.ReadFile(keyFile); err == nil {
			if _, err := tls.X509KeyPair(certData, keyData); err == nil {
				a.PublicCrt = certData
				a.PrivateKey = keyData
				return
			}
		}
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("generate rsa key err: ", err)
		return
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		serialNumber = big.NewInt(time.Now().UnixNano())
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         "ResDownloader Private Root CA",
			Organization:       []string{"ResDownloader Safe Local"},
			OrganizationalUnit: []string{"Security"},
			Country:            []string{"CN"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().AddDate(20, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		fmt.Println("create ca cert err: ", err)
		return
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		privKeyBytes = x509.MarshalPKCS1PrivateKey(privKey)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})

	_ = os.WriteFile(certFile, certPEM, 0644)
	_ = os.WriteFile(keyFile, keyPEM, 0600)

	a.PublicCrt = certPEM
	a.PrivateKey = keyPEM
}
