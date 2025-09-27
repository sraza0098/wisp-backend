package main

import (
  "github.com/gofiber/fiber/v2"
  "time"
  "os"
)

func main() {
  app := fiber.New()

  app.Get("/", func(c *fiber.Ctx) error {
    return c.SendString("Wisp backend is up ✅\nTry /health, /time, /version")
  })

  app.Get("/health", func(c *fiber.Ctx) error {
    return c.SendString("ok")
  })

  app.Get("/time", func(c *fiber.Ctx) error {
    return c.JSON(fiber.Map{"utc": time.Now().UTC()})
  })

  app.Get("/version", func(c *fiber.Ctx) error {
    return c.JSON(fiber.Map{"version": os.Getenv("WISP_VERSION")})
  })

  app.Listen(":8080")
}
