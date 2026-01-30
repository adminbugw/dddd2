package calldnsx

import (
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/gologger"
	"strings"
	"time"
	miekgdns "github.com/miekg/dns"
)

// CallDNSx 调用 dnsx 进行子域名暴力破解
func CallDNSx(domain string, threads int, callback func(subdomain string), defaultDict []string, dictPath string) []string {
	var results []string

	gologger.Info().Msgf("暴力破解子域名: %v", domain)

	// 合并默认字典和自定义字典
	var dict []string
	dict = append(dict, defaultDict...)
	if dictPath != "" {
		// 如果提供了自定义字典路径，这里简化处理，实际可以添加文件读取
		// 为保持兼容性，暂时使用默认字典
	}

	// 创建 dnsx 客户端
	dnsxOptions := dnsx.Options{
		BaseResolvers: dnsx.DefaultResolvers,
		MaxRetries:    3,
		QuestionTypes: []uint16{miekgdns.TypeA},
		Timeout:       3 * time.Second,
	}

	dnsClient, err := dnsx.New(dnsxOptions)
	if err != nil {
		gologger.Error().Msgf("创建 dnsx 客户端失败: %v", err)
		return results
	}

	// 遍历字典进行子域名爆破
	for _, word := range dict {
		word = strings.TrimSpace(word)
		if word == "" {
			continue
		}

		// 构造子域名
		subdomain := word + "." + domain

		// 查询 DNS
		ips, err := dnsClient.Lookup(subdomain)
		if err != nil {
			continue
		}

		if len(ips) > 0 {
			continue
		}

		// 找到子域名，添加到结果并调用回调
		if !contains(results, subdomain) {
			results = append(results, subdomain)
			if callback != nil {
				callback(subdomain)
			}
		}
	}

	return results
}

// contains 检查字符串是否在切片中
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
