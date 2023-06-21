package middleware

import (
	"a21hc3NpZ25tZW50/model"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"net/http"
)

func Auth() gin.HandlerFunc {
	return gin.HandlerFunc(func(ctx *gin.Context) {
		cookie, err := ctx.Request.Cookie("session_token")
		if err != nil {
			if err == http.ErrNoCookie {
				if ctx.ContentType() == "application/json" {
					ctx.JSON(http.StatusUnauthorized, model.ErrorResponse{Error: "Unauthorized"})
					ctx.Abort()
					return
				}
				ctx.JSON(http.StatusSeeOther, model.ErrorResponse{Error: "Unauthorized"})
				ctx.Abort()
				return
			}
			ctx.JSON(http.StatusBadRequest, model.ErrorResponse{Error: "bad request"})
			ctx.Abort()
			return
		}
		tokenString := cookie.Value
		if tokenString == "" {
			ctx.JSON(http.StatusUnauthorized, model.ErrorResponse{Error: "Token is missing"})
			ctx.Abort()
			return
		}

		customClaims := &model.Claims{}
		tkn, err := jwt.ParseWithClaims(tokenString, customClaims, func(token *jwt.Token) (interface{}, error) {
			return model.JwtKey, nil
		})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				ctx.JSON(http.StatusUnauthorized, model.ErrorResponse{Error: "Unauthorized"})
				ctx.Abort()
				return
			}
			ctx.JSON(http.StatusBadRequest, model.ErrorResponse{Error: "bad request"})
			ctx.Abort()
			return
		}
		if !tkn.Valid {
			ctx.JSON(http.StatusUnauthorized, model.ErrorResponse{Error: "Unauthorized"})
			ctx.Abort()
			return
		}
		ctx.Set("email", customClaims.Email)
		ctx.Next()
	})
}
