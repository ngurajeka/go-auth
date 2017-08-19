package auth

import (
	"encoding/gob"
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/gin-contrib/sessions"
)

const (
	// USER as global key identifier when storing data into session
	USER = "user"
)

const (
	// StatusInactive represent user with inactive status
	StatusInactive = false
	// StatusActive represent user with active status
	StatusActive = true
)

var (
	// ErrMissmatch displaying error message when user failed to be authenticated
	ErrMissmatch = errors.New("missmatch username / password combination")
	// ErrUserDuplicate displaying error message when the same user has been registered
	ErrUserDuplicate = errors.New("user duplicate")
	// ErrNotFound displaying error message when user has not been found
	ErrNotFound = errors.New("user not found")
	// ErrInactive displaying error message when user has inactive status
	ErrInactive = errors.New("inactive user")
)

// UserModel data
type UserModel interface {
	SetID(uint64)
	SetIsActive(bool)
	SetCreatedTime(time.Time)
	GetID() uint64
	GetFirstName() *string
	GetLastName() *string
	GetUsername() string
	GetPassword() []byte
	GetIsActive() bool
	TableName() string
}

// Repository talk to database
type Repository interface {
	Find(uint64) (UserModel, error)
	FindByUsername(string) (UserModel, error)
	FindAll() ([]UserModel, error)
	Store(UserModel) (UserModel, error)
	Update(UserModel) (UserModel, error)
	Remove(uint64) error
}

// Module for Authentication
type Module struct {
	repo    Repository
	session sessions.Session
}

// User data to store in session
type User struct {
	UserID              uint64
	Username            string
	FirstName, LastName *string
}

func init() {
	gob.Register(User{})
}

// New create new Authentication Module
func New(repo Repository) Module {
	return Module{repo: repo}
}

// UpdateSession replacing current sessions.Session in the module
func (mod *Module) UpdateSession(sess sessions.Session) {
	mod.session = sess
}

// CreateNewUser storing new user data into repository
func (mod *Module) CreateNewUser(user UserModel) (UserModel, error) {
	var err error
	// check username exist
	if _, err = mod.repo.FindByUsername(user.GetUsername()); err != ErrNotFound {
		return user, ErrUserDuplicate
	}
	// making sure user is not active and created time is utc.now
	user.SetIsActive(StatusInactive)
	user.SetCreatedTime(time.Now().UTC())
	// storing data
	if user, err = mod.repo.Store(user); err != nil {
		return user, err
	}
	return user, nil
}

// Authenticate verify username and password is match with bcrypt Encryption
func (mod *Module) Authenticate(user UserModel, password string) (UserModel, error) {
	// check username exist and active
	if user, err := mod.repo.FindByUsername(user.GetUsername()); err != nil {
		return user, err
	}
	if !user.GetIsActive() {
		return user, ErrInactive
	}
	// compare []byte(password) and []byte(user.Password) data
	if err := bcrypt.CompareHashAndPassword(user.GetPassword(), []byte(password)); err != nil {
		return user, ErrMissmatch
	}
	// storing into session
	mod.session.Set(USER, User{
		UserID:    user.GetID(),
		Username:  user.GetUsername(),
		FirstName: user.GetFirstName(),
		LastName:  user.GetLastName(),
	})
	err := mod.session.Save()
	return user, err
}

// Deauthenticate delete user from current session
func (mod *Module) Deauthenticate() error {
	mod.session.Delete(USER)
	return mod.session.Save()
}

// IsAuthenticated helper to check whether current session
// has been authenticated or not
func (mod *Module) IsAuthenticated() bool {
	model, err := mod.User()
	if err != nil {
		return false
	}
	return model.UserID != 0
}

// User returning user data from session
func (mod *Module) User() (User, error) {
	var (
		ok    bool
		model User
	)
	if model, ok = mod.session.Get(USER).(User); !ok {
		return model, errors.New("user not found")
	}
	return model, nil
}
