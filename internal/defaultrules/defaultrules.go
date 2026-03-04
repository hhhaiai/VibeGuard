package defaultrules

import (
	_ "embed"
	"log/slog"
	"os"
	"path/filepath"
)

//go:embed default.vgrules
var DefaultRules []byte

// EnsureInstalled writes the embedded default rules to the given path if the file does not exist.
func EnsureInstalled(path string) {
	if _, err := os.Stat(path); err == nil {
		return
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		slog.Warn("创建默认规则目录失败", "error", err)
		return
	}
	// Rule files typically do not contain secrets, but using the same minimal permissions as other rule caches (0600) is safer.
	if err := os.WriteFile(path, DefaultRules, 0o600); err != nil {
		slog.Warn("写入默认规则文件失败", "error", err)
		return
	}
	slog.Info("已安装默认规则", "path", path)
}
