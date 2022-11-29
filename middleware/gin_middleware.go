package middleware

import (
	"strings"

	"github.com/vins7/module-middleware/middleware/model"
	"github.com/vins7/module-middleware/middleware/util"

	"github.com/gin-gonic/gin"
)

func (j *JWTManager) Middleware(secretKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		h := model.GinMiddleware{}
		user := &model.UserClaims{}
		if err := c.ShouldBindHeader(&h); err != nil {

			err := util.NewInternal()
			c.JSON(err.Status(), gin.H{
				"error": err,
			})
			c.Abort()
			return
		}

		idTokenHeader := strings.Split(h.IDToken, "Bearer ")

		if len(idTokenHeader) < 2 {
			err := util.NewAuthorization("Must provide Authorization header with format `Bearer {token}`")

			c.JSON(err.Status(), gin.H{
				"error": err,
			})
			c.Abort()
			return
		}

		user, err := ValidateIDToken(idTokenHeader[1], j.secretKey)
		if err != nil {
			err := util.NewAuthorization("Provided token is invalid")
			c.JSON(err.Status(), gin.H{
				"error": err,
			})
			c.Abort()
			return
		}

		c.Set("user-data", user)
		c.Next()
	}
}
