// Copyright 2018 Axel Etcheverry. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	stdlog "log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/asdine/storm"
	"github.com/euskadi31/go-server"
	"github.com/euskadi31/go-server/authentication"
	"github.com/euskadi31/go-service"
	"github.com/hyperscale/hypercheck/cmd/hypercheck-api/authenticate"
	"github.com/hyperscale/hypercheck/cmd/hypercheck-api/controller"
	"github.com/hyperscale/hypercheck/cmd/hypercheck-api/storage"
	"github.com/hyperscale/hypercheck/config"
	"github.com/hyperscale/hypercheck/version"
	"github.com/rs/cors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

const applicationName = "hypercheck-api"

// Service Container
var container = service.New()

var (
	basePath = "/var/lib/" + applicationName
)

// const of service name
const (
	ServiceLoggerKey                  string = "service.logger"
	ServiceConfigKey                         = "service.config"
	ServiceRouterKey                         = "service.router"
	ServiceAuthControllerKey                 = "service.controller.auth"
	ServiceUserControllerKey                 = "service.controller.user"
	ServiceStormDBKey                        = "service.db.storm"
	ServiceUserStorageKey                    = "service.storage.user"
	ServiceJWTAuthenticateProviderKey        = "service.auth.provider.jwt"
	ServiceAuthMiddlewareKey                 = "service.middleware.auth"
)

func init() {
	// Logger Service
	container.Set(ServiceLoggerKey, func(c *service.Container) interface{} {
		cfg := c.Get(ServiceConfigKey).(*config.Configuration)

		logger := zerolog.New(os.Stdout).With().
			Timestamp().
			Str("role", cfg.Logger.Prefix).
			Str("version", version.Version.String()).
			Logger()

		zerolog.SetGlobalLevel(cfg.Logger.Level())

		fi, _ := os.Stdin.Stat()
		if (fi.Mode() & os.ModeCharDevice) != 0 {
			logger = logger.Output(zerolog.ConsoleWriter{Out: os.Stderr})
		}

		stdlog.SetFlags(0)
		stdlog.SetOutput(logger)

		log.Logger = logger

		return logger
	})

	// Config Service
	container.Set(ServiceConfigKey, func(c *service.Container) interface{} {
		var cfgFile string
		cmd := flag.NewFlagSet(os.Args[0], flag.ExitOnError)

		cmd.StringVar(&cfgFile, "config", "", "config file (default is $HOME/config.yaml)")

		// Ignore errors; cmd is set for ExitOnError.
		cmd.Parse(os.Args[1:])

		options := viper.New()

		if cfgFile != "" { // enable ability to specify config file via flag
			options.SetConfigFile(cfgFile)
		}

		options.SetDefault("server.host", "")
		options.SetDefault("server.port", 8080)
		options.SetDefault("server.shutdown_timeout", 10*time.Second)
		options.SetDefault("server.write_timeout", 10*time.Second)
		options.SetDefault("server.read_timeout", 10*time.Second)
		options.SetDefault("server.read_header_timeout", 10*time.Millisecond)
		options.SetDefault("logger.level", "info")
		options.SetDefault("logger.prefix", applicationName)
		options.SetDefault("database.path", basePath)
		options.SetDefault("doc.enable", true)
		options.SetDefault("auth.realm", "Hypercheck")

		options.SetConfigName("config") // name of config file (without extension)

		options.AddConfigPath("./etc/" + applicationName + "/")
		options.AddConfigPath("/etc/" + applicationName + "/")   // path to look for the config file in
		options.AddConfigPath("$HOME/." + applicationName + "/") // call multiple times to add many search paths
		options.AddConfigPath(".")

		if port := os.Getenv("PORT"); port != "" {
			os.Setenv("HYPERCHECK_API_SERVER_PORT", port)
		}

		options.SetEnvPrefix("HYPERCHECK_API")
		options.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
		options.AutomaticEnv() // read in environment variables that match

		// If a config file is found, read it in.
		if err := options.ReadInConfig(); err == nil {
			log.Info().Msgf("Using config file: %s", options.ConfigFileUsed())
		}

		return config.NewConfiguration(options)
	})

	container.Set(ServiceStormDBKey, func(c *service.Container) interface{} {
		cfg := c.Get(ServiceConfigKey).(*config.Configuration)

		path := strings.TrimRight(cfg.Database.Path, "/")

		db, err := storm.Open(fmt.Sprintf("%s/hypercheck.db", path))
		if err != nil {
			log.Fatal().Err(err).Msg(ServiceStormDBKey)
		}

		return db
	})

	container.Set(ServiceJWTAuthenticateProviderKey, func(c *service.Container) interface{} {
		cfg := c.Get(ServiceConfigKey).(*config.Configuration)
		userStorage := c.Get(ServiceUserStorageKey).(storage.UserStorage)

		auth := authenticate.NewJWTProvider(cfg.Database.Path, userStorage)

		if !auth.HasKey() {
			log.Info().Msg("Generate RSA key...")

			if err := auth.GenerateKey(); err != nil {
				log.Fatal().Err(err)
			}
		}

		if err := auth.LoadKeys(); err != nil {
			log.Fatal().Err(err)
		}

		return auth
	})

	container.Set(ServiceUserStorageKey, func(c *service.Container) interface{} {
		db := c.Get(ServiceStormDBKey).(*storm.DB)

		return storage.NewUserStorage(db)
	})

	container.Set(ServiceAuthControllerKey, func(c *service.Container) interface{} {
		userStorage := c.Get(ServiceUserStorageKey).(storage.UserStorage)
		authProvider := c.Get(ServiceJWTAuthenticateProviderKey).(*authenticate.JWTProvider)

		return controller.NewAuthController(userStorage, authProvider)
	})

	container.Set(ServiceAuthMiddlewareKey, func(c *service.Container) interface{} {
		cfg := c.Get(ServiceConfigKey).(*config.Configuration)
		authProvider := c.Get(ServiceJWTAuthenticateProviderKey).(authentication.Provider)

		return authentication.Handler(cfg.Auth, authProvider)
	})

	container.Set(ServiceUserControllerKey, func(c *service.Container) interface{} {
		userStorage := c.Get(ServiceUserStorageKey).(storage.UserStorage)
		authMiddleware := c.Get(ServiceAuthMiddlewareKey).(func(http.Handler) http.Handler)

		return controller.NewUserController(userStorage, authMiddleware)
	})

	// Router Service
	container.Set(ServiceRouterKey, func(c *service.Container) interface{} {
		logger := c.Get(ServiceLoggerKey).(zerolog.Logger)
		cfg := c.Get(ServiceConfigKey).(*config.Configuration)
		userController := c.Get(ServiceUserControllerKey).(server.Controller)
		authController := c.Get(ServiceAuthControllerKey).(server.Controller)
		// docController := c.Get(ServiceDocControllerKey).(server.Controller)

		corsHandler := cors.New(cors.Options{
			AllowCredentials: false,
			AllowedOrigins:   []string{"*"},
			AllowedMethods: []string{
				http.MethodGet,
				http.MethodOptions,
				http.MethodPost,
				http.MethodPut,
				http.MethodDelete,
			},
			AllowedHeaders: []string{
				"Authorization",
				"Content-Type",
			},
			Debug: cfg.Server.Debug,
		})

		router := server.NewRouter()

		router.Use(hlog.NewHandler(logger))
		router.Use(hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
			hlog.FromRequest(r).Info().
				Str("method", r.Method).
				Str("url", r.URL.String()).
				Int("status", status).
				Int("size", size).
				Dur("duration", duration).
				Msg(fmt.Sprintf("%s %s", r.Method, r.URL.String()))
		}))
		router.Use(hlog.RemoteAddrHandler("ip"))
		router.Use(hlog.UserAgentHandler("user_agent"))
		router.Use(hlog.RefererHandler("referer"))
		router.Use(hlog.RequestIDHandler("req_id", "Request-Id"))
		router.Use(corsHandler.Handler)

		router.EnableHealthCheck()
		router.EnableMetrics()

		// if cfg.Doc.Enable {
		// router.AddController(docController)
		// }

		router.AddController(authController)
		router.AddController(userController)

		return router
	})
}
