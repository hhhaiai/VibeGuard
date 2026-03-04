package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/inkdust2021/vibeguard/internal/pii_next/keywords"
	"github.com/inkdust2021/vibeguard/internal/pii_next/ner"
	"github.com/inkdust2021/vibeguard/internal/pii_next/pipeline"
	"github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"
	"github.com/inkdust2021/vibeguard/internal/pii_next/rulelist"
	"github.com/inkdust2021/vibeguard/internal/session"
)

// Example:
//
//	echo "hi I'm Samuel Porter. My email is Samuel@gmail.com." | go run ./internal/pii_next/demo --keyword "Samuel Porter" --rulelist "docs/rule_lists.sample.vgrules"
func main() {
	var (
		textFlag       = flag.String("text", "", "要脱敏的文本（留空则从 stdin 读取）")
		keywordFlags   = flag.String("keyword", "", "关键词（可用逗号分隔多个，例如: \"foo,bar\"）")
		ruleListFlags  = flag.String("rulelist", "", "规则列表文件路径（.vgrules，可用逗号分隔多个）")
		ruleListPrio   = flag.Int("rulelist-priority", 50, "规则列表优先级（1~99；与关键词/其他规则冲突时用于消解）")
		nerEnabled     = flag.Bool("ner", false, "启用 NER（Presidio Analyzer 实体识别）")
		nerPresidioURL = flag.String("ner-presidio-url", "http://127.0.0.1:5001", "Presidio Analyzer base URL (calls /analyze)")
		nerLanguage    = flag.String("ner-language", "auto", "NER 语言参数（auto/en/zh/...）")
		nerEntities    = flag.String("ner-entities", "", "实体类型（逗号分隔，例如: \"PERSON,ORG,LOCATION\"；留空使用默认）")
		nerMinScore    = flag.Float64("ner-min-score", 0, "NER 最小置信度（0~1；0 表示默认）")
		nerTimeout     = flag.Duration("ner-timeout", 800*time.Millisecond, "Presidio 请求超时")
		nerConc        = flag.Int("ner-concurrency", 2, "Presidio 最大并发（<=0 表示不限制）")
		showOriginal   = flag.Bool("show-original", false, "输出命中详情时显示原文（默认不显示）")
		deterministic  = flag.Bool("deterministic", true, "使用稳定占位符（HMAC 固定 key；便于对比测试）")
		sessionTTL     = flag.Duration("ttl", 1*time.Hour, "会话映射有效期")
		sessionMaxSize = flag.Int("max", 100000, "会话映射最大条目数")
	)
	flag.Parse()

	input := *textFlag
	if input == "" {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintln(os.Stderr, "读取 stdin 失败：", err)
			os.Exit(2)
		}
		input = string(b)
	}

	sess := session.NewManager(*sessionTTL, *sessionMaxSize)
	defer sess.Close()
	if *deterministic {
		key32 := make([]byte, 32)
		for i := range key32 {
			key32[i] = byte(i)
		}
		_ = sess.SetDeterministicPlaceholders(true, key32)
	}

	var recs []recognizer.Recognizer
	if *keywordFlags != "" {
		var kws []keywords.Keyword
		for _, k := range strings.Split(*keywordFlags, ",") {
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			kws = append(kws, keywords.Keyword{Text: k, Category: "TEXT"})
		}
		if len(kws) > 0 {
			recs = append(recs, keywords.New(kws))
		}
	}
	if strings.TrimSpace(*ruleListFlags) != "" {
		for _, p := range strings.Split(*ruleListFlags, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			rec, err := rulelist.ParseFile(p, rulelist.ParseOptions{
				Name:     filepath.Base(p),
				Priority: *ruleListPrio,
			})
			if err != nil {
				fmt.Fprintln(os.Stderr, "加载规则列表失败：", err)
				os.Exit(2)
			}
			recs = append(recs, rec)
		}
	}

	if *nerEnabled {
		var ents []string
		if strings.TrimSpace(*nerEntities) != "" {
			for _, e := range strings.Split(*nerEntities, ",") {
				e = strings.TrimSpace(e)
				if e == "" {
					continue
				}
				ents = append(ents, e)
			}
		}
		rec, err := ner.New(ner.Options{
			PresidioURL:    *nerPresidioURL,
			Language:       *nerLanguage,
			Entities:       ents,
			MinScore:       *nerMinScore,
			Timeout:        *nerTimeout,
			MaxConcurrency: *nerConc,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "初始化 NER 失败：", err)
			os.Exit(2)
		}
		if rec != nil {
			recs = append(recs, rec)
		}
	}

	p := pipeline.New(sess, "__VG_", recs...)
	out, matches := p.RedactWithMatches([]byte(input))

	fmt.Println(string(out))

	type item struct {
		Category    string `json:"category"`
		Placeholder string `json:"placeholder"`
		Start       int    `json:"start"`
		End         int    `json:"end"`
		Original    string `json:"original,omitempty"`
	}
	items := make([]item, 0, len(matches))
	for _, m := range matches {
		it := item{
			Category:    m.Category,
			Placeholder: m.Placeholder,
			Start:       m.Start,
			End:         m.End,
		}
		if *showOriginal {
			it.Original = m.Original
		}
		items = append(items, it)
	}
	b, _ := json.MarshalIndent(items, "", "  ")
	fmt.Println(string(b))
}
