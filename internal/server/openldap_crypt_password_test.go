package server

import (
	"context"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPBindOpenLDAPCryptVectors(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		stored   string
		password string
	}{
		{
			name:     "traditional DES",
			stored:   "{CRYPT}aajfMKNH1hTm2",
			password: "password",
		},
		{
			name:     "MD5 crypt",
			stored:   "{CRYPT}$1$12345678$o2n/JiO/h5VviOInWJ4OQ/",
			password: "password",
		},
		{
			name:     "bcrypt 2a",
			stored:   "{CRYPT}$2a$05$abcdefghijklmnopqrstuuWG29KuyeAicPCJODk1zjyGvyQUU2awu",
			password: "password",
		},
		{
			name:     "bcrypt 2b",
			stored:   "{CRYPT}$2b$05$abcdefghijklmnopqrstuuWG29KuyeAicPCJODk1zjyGvyQUU2awu",
			password: "password",
		},
		{
			name:     "bcrypt 2y",
			stored:   "{CRYPT}$2y$05$abcdefghijklmnopqrstuuWG29KuyeAicPCJODk1zjyGvyQUU2awu",
			password: "password",
		},
		{
			name:     "SHA256 crypt",
			stored:   "{CRYPT}$5$1234567890abcdef$Y9E1oV2b5rfo0XbJievQAAPfdOUEfVNWacVfdrP0bo4",
			password: "password",
		},
		{
			name:     "SHA512 crypt",
			stored:   "{CRYPT}$6$1234567890abcdef$CBFXtqpRR1ddYz1RnbP5n/T3SopKJ/m5cWFMZimwP60dam5WZuLumvWttgtCq/QBTxGOp9.Ts3KepQ8O.RuyL/",
			password: "password",
		},
		{
			name:     "SM3 crypt",
			stored:   "{CRYPT}$sm3$rounds=1000$saltstring$rA2ewUHqiQH5Le9o318IWjgsADyZCgfFXofbx1T1NCD",
			password: "abc",
		},
		{
			name:     "SM3 yescrypt",
			stored:   "{CRYPT}$sm3y$j75$.......$duiiYQVhOT63KI.mAoLYbyaDvBu8kRypgtoCouFp3r8",
			password: "abc",
		},
		{
			name:     "GOST yescrypt",
			stored:   "{CRYPT}$gy$j75$.......$XH2YP.u9tPw6ObDCXTRJiUfyrAEZ/TGIF0CjnxNW3h/",
			password: "abc",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedDirectory(t, store)
			if err := store.Update(t.Context(), func(writer storage.Writer) error {
				dn, err := directory.ParseDN(aliceDN)
				if err != nil {
					return err
				}
				entry, err := writer.Get(dn)
				if err != nil {
					return err
				}
				entry.ReplaceValues("userPassword", [][]byte{[]byte(test.stored)})
				return writer.Put(entry, true)
			}); err != nil {
				t.Fatalf("store CRYPT password: %v", err)
			}
			address, stop := startServer(t, store, Config{})
			defer stop()
			assertBindPassword(t, address, aliceDN, test.password, true)
			assertBindPassword(t, address, aliceDN, "wrong-password", false)
		})
	}
}

func TestLDAPBindRejectsUnsupportedOpenLDAPCrypt(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN(aliceDN)
		if err != nil {
			return err
		}
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("userPassword", [][]byte{[]byte("{CRYPT}$y$j9T$salt$hash")})
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("store unsupported CRYPT password: %v", err)
	}
	address, stop := startServer(t, store, Config{})
	defer stop()
	assertBindPassword(t, address, aliceDN, "password", false)
}
