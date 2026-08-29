// Package managed provides the hardened Redis ACL auth provider profile.
package managed

import "github.com/dash-xd/ratelimiter/auth"

const DefaultAdminUser = "application-admin"

type Config struct {
	AdminUser      string
	UsernamePrefix string
	KeyPrefix      string
	ChannelPrefix  string
	FunctionPrefix string
}

func New(config Config) (auth.Provider, error) {
	if config.AdminUser == "" {
		config.AdminUser = DefaultAdminUser
	}
	return auth.NewRedisACLProvider(auth.RedisACLConfig{
		Name:           "managed",
		Admin:          config.AdminUser,
		UsernamePrefix: config.UsernamePrefix,
		KeyPrefix:      config.KeyPrefix,
		ChannelPrefix:  config.ChannelPrefix,
		FunctionPrefix: config.FunctionPrefix,
	})
}
