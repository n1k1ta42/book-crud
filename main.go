package main

import (
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/swaggo/files"
	"github.com/swaggo/gin-swagger"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	_ "book-crud/docs"
)

// @title Library API
// @version 1.0
// @description This is a sample server for a library.
// @termsOfService https://example.com/terms/

// @contact.name API Support
// @contact.url http://www.example.com/support
// @contact.email support@example.com

// @license.name MIT
// @license.url https://opensource.org/licenses/MIT

// @host localhost:8080
// @BasePath /

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization

type Author struct {
	ID      uint   `json:"id" gorm:"primaryKey"`
	Name    string `json:"name"`
	Country string `json:"country"`
	Books   []Book `json:"books"`
}

type Book struct {
	ID       uint   `json:"id" gorm:"primaryKey"`
	Title    string `json:"title"`
	Genre    string `json:"genre"`
	AuthorID uint   `json:"author_id"`
	Author   Author `json:"author" gorm:"foreignKey:AuthorID"`
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type TokenResponse struct {
	Token string `json:"token"`
}

var db *gorm.DB
var err error
var jwtKey = []byte("secret_key")

func main() {
	// Initialize the database
	db, err = gorm.Open(sqlite.Open("library.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	// Migrate the schema
	db.AutoMigrate(&Author{}, &Book{})

	// Initialize Gin router
	r := gin.Default()

	r.Use(CORSMiddleware())

	// Swagger documentation
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Public routes
	r.POST("/login", login)

	// Protected routes
	protected := r.Group("/")
	protected.Use(authMiddleware())
	{
		protected.GET("/authors", getAuthors)
		protected.GET("/authors/:id", getAuthorByID)
		protected.POST("/authors", createAuthor)
		protected.PUT("/authors/:id", updateAuthor)
		protected.DELETE("/authors/:id", deleteAuthor)
		protected.GET("/books", getBooks)
		protected.GET("/books/:id", getBookByID)
		protected.POST("/books", createBook)
		protected.PUT("/books/:id", updateBook)
		protected.DELETE("/books/:id", deleteBook)
	}

	// Run the server
	r.Run(":3000")
}

// @Summary Login
// @Description Login and get token
// @Tags auth
// @Accept json
// @Produce json
// @Param user body User true "User credentials"
// @Success 200 {object} TokenResponse
// @Failure 401 {object} ErrorResponse
// @Router /login [post]
func login(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid request"})
		return
	}

	// For simplicity, using hardcoded username and password
	if user.Username != "admin" || user.Password != "password" {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Invalid credentials"})
		return
	}

	// Create the JWT claims, which includes the username and expiry time
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &jwt.StandardClaims{
		ExpiresAt: expirationTime.Unix(),
		Subject:   user.Username,
	}

	// Create the JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Could not create token"})
		return
	}

	// Send the token back to the client
	c.JSON(http.StatusOK, TokenResponse{Token: tokenString})
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Authorization header missing"})
			c.Abort()
			return
		}

		claims := &jwt.StandardClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Invalid token"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// getAuthors godoc
// @Summary Get all authors
// @Description Get list of all authors
// @Tags authors
// @Produce json
// @Param name query string false "Filter by name"
// @Param country query string false "Filter by country"
// @Success 200 {array} Author
// @Security BearerAuth
// @Router /authors [get]
func getAuthors(c *gin.Context) {
	var authors []Author
	query := db.Preload("Books")

	if name := c.Query("name"); name != "" {
		query = query.Where("name LIKE ?", "%"+name+"%")
	}

	if country := c.Query("country"); country != "" {
		query = query.Where("country LIKE ?", "%"+country+"%")
	}

	query.Find(&authors)
	c.JSON(http.StatusOK, authors)
}

// getAuthorByID godoc
// @Summary Get author by ID
// @Description Get a single author by ID
// @Tags authors
// @Produce json
// @Param id path uint true "Author ID"
// @Success 200 {object} Author
// @Failure 404 {object} ErrorResponse
// @Security BearerAuth
// @Router /authors/{id} [get]
func getAuthorByID(c *gin.Context) {
	id := c.Param("id")
	var author Author
	if result := db.Preload("Books").First(&author, id); result.Error != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "Author not found"})
		return
	}
	c.JSON(http.StatusOK, author)
}

// createAuthor godoc
// @Summary Create a new author
// @Description Create a new author
// @Tags authors
// @Accept json
// @Produce json
// @Param author body Author true "Author to create"
// @Success 201 {object} Author
// @Security BearerAuth
// @Router /authors [post]
func createAuthor(c *gin.Context) {
	var author Author
	if err := c.ShouldBindJSON(&author); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	db.Create(&author)
	c.JSON(http.StatusCreated, author)
}

// updateAuthor godoc
// @Summary Update an existing author
// @Description Update an existing author
// @Tags authors
// @Accept json
// @Produce json
// @Param id path uint true "Author ID"
// @Param author body Author true "Author to update"
// @Success 200 {object} Author
// @Failure 404 {object} ErrorResponse
// @Security BearerAuth
// @Router /authors/{id} [put]
func updateAuthor(c *gin.Context) {
	id := c.Param("id")
	var author Author
	if result := db.First(&author, id); result.Error != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "Author not found"})
		return
	}
	if err := c.ShouldBindJSON(&author); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	db.Save(&author)
	c.JSON(http.StatusOK, author)
}

// deleteAuthor godoc
// @Summary Delete an author
// @Description Delete an author by ID
// @Tags authors
// @Param id path uint true "Author ID"
// @Success 204 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Security BearerAuth
// @Router /authors/{id} [delete]
func deleteAuthor(c *gin.Context) {
	id := c.Param("id")
	var author Author
	if result := db.First(&author, id); result.Error != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "Author not found"})
		return
	}
	db.Delete(&author)
	c.JSON(http.StatusNoContent, ErrorResponse{})
}

// getBooks godoc
// @Summary Get all books
// @Description Get list of all books
// @Tags books
// @Produce json
// @Param title query string false "Filter by title"
// @Param genre query string false "Filter by genre"
// @Param author_id query uint false "Filter by author ID"
// @Success 200 {array} Book
// @Security BearerAuth
// @Router /books [get]
func getBooks(c *gin.Context) {
	var books []Book
	query := db.Preload("Author")

	if title := c.Query("title"); title != "" {
		query = query.Where("title LIKE ?", "%"+title+"%")
	}

	if genre := c.Query("genre"); genre != "" {
		query = query.Where("genre LIKE ?", "%"+genre+"%")
	}

	if authorID := c.Query("author_id"); authorID != "" {
		query = query.Where("author_id = ?", authorID)
	}

	query.Find(&books)
	c.JSON(http.StatusOK, books)
}

// getBookByID godoc
// @Summary Get book by ID
// @Description Get a single book by ID
// @Tags books
// @Produce json
// @Param id path uint true "Book ID"
// @Success 200 {object} Book
// @Failure 404 {object} ErrorResponse
// @Security BearerAuth
// @Router /books/{id} [get]
func getBookByID(c *gin.Context) {
	id := c.Param("id")
	var book Book
	if result := db.Preload("Author").First(&book, id); result.Error != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "Book not found"})
		return
	}
	c.JSON(http.StatusOK, book)
}

// createBook godoc
// @Summary Create a new book
// @Description Create a new book
// @Tags books
// @Accept json
// @Produce json
// @Param book body Book true "Book to create"
// @Success 201 {object} Book
// @Security BearerAuth
// @Router /books [post]
func createBook(c *gin.Context) {
	var book Book
	if err := c.ShouldBindJSON(&book); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	db.Create(&book)
	c.JSON(http.StatusCreated, book)
}

// updateBook godoc
// @Summary Update an existing book
// @Description Update an existing book
// @Tags books
// @Accept json
// @Produce json
// @Param id path uint true "Book ID"
// @Param book body Book true "Book to update"
// @Success 200 {object} Book
// @Failure 404 {object} ErrorResponse
// @Security BearerAuth
// @Router /books/{id} [put]
func updateBook(c *gin.Context) {
	id := c.Param("id")
	var book Book
	if result := db.First(&book, id); result.Error != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "Book not found"})
		return
	}
	if err := c.ShouldBindJSON(&book); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	db.Save(&book)
	c.JSON(http.StatusOK, book)
}

// deleteBook godoc
// @Summary Delete a book
// @Description Delete a book by ID
// @Tags books
// @Param id path uint true "Book ID"
// @Success 204 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Security BearerAuth
// @Router /books/{id} [delete]
func deleteBook(c *gin.Context) {
	id := c.Param("id")
	var book Book
	if result := db.First(&book, id); result.Error != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "Book not found"})
		return
	}
	db.Delete(&book)
	c.JSON(http.StatusNoContent, ErrorResponse{})
}
