// Package managed provides the hardened local Redis ACL execution profile.
package managed

import "github.com/dash-xd/ratelimiter/redisacl"

const DefaultAdminUser = "application-admin"

type Config struct {
	AdminUser      string
	UsernamePrefix string
	KeyPrefix      string
	ChannelPrefix  string
	FunctionPrefix string
}

func New(config Config) (redisacl.Compiler, error) {
	if config.AdminUser == "" {
		config.AdminUser = DefaultAdminUser
	}
	return redisacl.New(redisacl.Config{
		Name:           "managed",
		Admin:          config.AdminUser,
		UsernamePrefix: config.UsernamePrefix,
		KeyPrefix:      config.KeyPrefix,
		ChannelPrefix:  config.ChannelPrefix,
		FunctionPrefix: config.FunctionPrefix,
	})
}
