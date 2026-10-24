package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ネットワーク鍵（外側の包み用）。世代ごとに1本の鎖があり、1分ごとに一方向に進める。
// 手元には「今の1分前」の鍵だけを残し、それより古い鍵は消す（前方秘匿性）。

const oldGenKeep = 7 * 24 * time.Hour

type chainState struct {
	Gen     int    `json:"gen"`
	T       int64  `json:"t"` // この鍵の分（Unix秒/60）
	K       string `json:"k"`
	Expires int64  `json:"expires,omitempty"` // 古い世代を聞き続ける期限
}

type keyFile struct {
	Chains []chainState `json:"chains"`
}

type slot struct {
	gen int
	t   int64
	k   [32]byte
}

func minuteOf(t time.Time) int64 { return t.Unix() / 60 }

func h(label string, k [32]byte) [32]byte {
	return sha256.Sum256(append([]byte(label), k[:]...))
}

func stepKey(k [32]byte) [32]byte { return h("nmesh/chain", k) }
func tagOf(k [32]byte) string     { t := h("nmesh/tag", k); return hex.EncodeToString(t[:16]) }
func encOf(k [32]byte) [32]byte   { return h("nmesh/enc", k) }

func randKey() [32]byte {
	var k [32]byte
	rand.Read(k[:])
	return k
}

func parseKey(s string) ([32]byte, error) {
	var k [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return k, fmt.Errorf("鍵の形式が不正")
	}
	copy(k[:], b)
	return k, nil
}

type keyring struct {
	dir string
	mu  sync.Mutex
	kf  keyFile
}

func (kr *keyring) path() string { return filepath.Join(kr.dir, "netkeys.json") }

// withFileLock は管理コマンドとデーモンが同時に鍵ファイルを書かないようにする。
func withFileLock(dir string, f func() error) error {
	fd, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer fd.Close()
	if err := syscall.Flock(int(fd.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(fd.Fd()), syscall.LOCK_UN)
	return f()
}

// update はロックを取り、ファイルを読み、f で変更し、鎖を今に進めて保存する。
func (kr *keyring) update(now time.Time, f func(kf *keyFile) error) error {
	return withFileLock(kr.dir, func() error {
		var kf keyFile
		if err := loadJSON(kr.path(), &kf); err != nil && !os.IsNotExist(err) {
			return err
		}
		if f != nil {
			if err := f(&kf); err != nil {
				return err
			}
		}
		advanceChains(&kf, now)
		if err := saveJSON(kr.path(), kf, 0600); err != nil {
			return err
		}
		kr.mu.Lock()
		kr.kf = kf
		kr.mu.Unlock()
		return nil
	})
}

func advanceChains(kf *keyFile, now time.Time) {
	target := minuteOf(now) - 1
	var keep []chainState
	for _, c := range kf.Chains {
		if c.Expires != 0 && now.Unix() > c.Expires {
			continue
		}
		k, err := parseKey(c.K)
		if err != nil {
			continue
		}
		for c.T < target {
			k = stepKey(k)
			c.T++
		}
		c.K = hex.EncodeToString(k[:])
		keep = append(keep, c)
	}
	sort.Slice(keep, func(i, j int) bool { return keep[i].Gen > keep[j].Gen })
	kf.Chains = keep
}

func (kr *keyring) current() (chainState, bool) {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	if len(kr.kf.Chains) == 0 {
		return chainState{}, false
	}
	return kr.kf.Chains[0], true
}

// slots は聞くべき鍵（各世代の t-1, t, t+1）を返す。
func (kr *keyring) slots(now time.Time) []slot {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	cur := minuteOf(now)
	var out []slot
	for _, c := range kr.kf.Chains {
		k, err := parseKey(c.K)
		if err != nil {
			continue
		}
		t := c.T
		for t < cur-1 {
			k = stepKey(k)
			t++
		}
		for ; t <= cur+1; t++ {
			out = append(out, slot{c.Gen, t, k})
			k = stepKey(k)
		}
	}
	return out
}

// sendSlot は世代 gen で今送るときの鍵。
func (kr *keyring) sendSlot(gen int, now time.Time) (slot, bool) {
	cur := minuteOf(now)
	for _, s := range kr.slots(now) {
		if s.gen == gen && s.t == cur {
			return s, true
		}
	}
	return slot{}, false
}

// addGen は新しい世代を足し、それより前の世代に聞き続ける期限を付ける。
func addGen(kf *keyFile, c chainState, now time.Time) bool {
	for _, x := range kf.Chains {
		if x.Gen >= c.Gen {
			return false
		}
	}
	for i := range kf.Chains {
		if kf.Chains[i].Expires == 0 {
			kf.Chains[i].Expires = now.Add(oldGenKeep).Unix()
		}
	}
	c.Expires = 0
	kf.Chains = append(kf.Chains, c)
	return true
}

// ---- 招待 ----

type invite struct {
	V      int      `json:"v"`
	Net    string   `json:"net"`
	Admin  string   `json:"admin"`
	For    string   `json:"for"`
	Relays []string `json:"relays"`
	Gen    int      `json:"gen"`
	T      int64    `json:"t"`
	K      string   `json:"k"`
}

const invitePrefix = "nmesh-invite:"

func (iv invite) String() string {
	b, _ := json.Marshal(iv)
	return invitePrefix + base64.RawURLEncoding.EncodeToString(b)
}

func parseInvite(s string) (invite, error) {
	var iv invite
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, invitePrefix) {
		return iv, fmt.Errorf("招待文字列ではありません")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, invitePrefix))
	if err != nil {
		return iv, err
	}
	if err := json.Unmarshal(b, &iv); err != nil {
		return iv, err
	}
	if _, err := parseKey(iv.K); err != nil || iv.V != 1 || iv.Net == "" || len(iv.Admin) != 64 {
		return iv, fmt.Errorf("招待文字列が壊れています")
	}
	return iv, nil
}
