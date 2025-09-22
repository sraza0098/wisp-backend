package main
import ( "os"; "time"; "github.com/gofiber/fiber/v2" )
func main(){
  app := fiber.New()
  app.Get("/health", func(c *fiber.Ctx) error { return c.SendString("ok") })
  app.Get("/version", func(c *fiber.Ctx) error { return c.JSON(fiber.Map{"version": os.Getenv("WISP_VERSION")}) })
  app.Get("/time", func(c *fiber.Ctx) error { return c.JSON(fiber.Map{"utc": time.Now().UTC()}) })
  app.Listen(":8080")
}
