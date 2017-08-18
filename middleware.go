package auth

import (
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

const AUTH_KEY = "auth"

// AuthHandler store session into module
func AuthHandler(mod Module) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		mod.UpdateSession(sessions.Default(ctx))
		ctx.Set(AUTH_KEY, mod)
		ctx.Next()
	}
}

// UserRestricted is a middleware to restrict
// some route for authenticated user only
func UserRestricted() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var (
			mod Module
			ok  bool
		)
		r := map[string]interface{}{
			"message": "unauthorized",
		}
		if mod, ok = ctx.MustGet(AUTH_KEY).(Module); !ok {
			ctx.JSON(http.StatusUnauthorized, r)
			ctx.AbortWithStatus(http.StatusUnauthorized)
		}
		if !mod.IsAuthenticated() {
			ctx.JSON(http.StatusUnauthorized, r)
			ctx.AbortWithStatus(http.StatusUnauthorized)
		}
	}
}
