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
	// StatusActive represent user with active status
	StatusActive = true
	// StatusInactive represent user with inactive status
	StatusInactive = false
)

var (
	// ErrAlreadyActived displaying error messeage when user has already activated
	ErrAlreadyActived = errors.New("user already actived")
	// ErrAlreadyInactived displaying error messeage when user has already Inactivated
	ErrAlreadyInactived = errors.New("user already inactived")
	// ErrInactive displaying error message when user has inactive status
	ErrInactive = errors.New("inactive user")
	// ErrMissmatch displaying error message when user failed to be authenticated
	ErrMissmatch = errors.New("missmatch username / password combination")
	// ErrNotFound displaying error message when user has not been found
	ErrNotFound = errors.New("user not found")
	// ErrUserDuplicate displaying error message when the same user has been registered
	ErrUserDuplicate = errors.New("user duplicate")
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

// ActivateUser set inactive user as active
func (mod *Module) ActivateUser(user UserModel) (UserModel, error) {
	if user.GetIsActive() {
		return user, ErrAlreadyActived
	}
	user.SetIsActive(true)
	return mod.repo.Update(user)
}

// Authenticate verify username and password is match with bcrypt Encryption
func (mod *Module) Authenticate(user UserModel, password string) (UserModel, error) {
	var err error
	// check username exist and active
	if user, err = mod.repo.FindByUsername(user.GetUsername()); err != nil {
		return user, err
	}
	if !user.GetIsActive() {
		return user, ErrInactive
	}
	// compare []byte(password) and []byte(user.Password) data
	if err = bcrypt.CompareHashAndPassword(user.GetPassword(), []byte(password)); err != nil {
		return user, ErrMissmatch
	}
	// storing into session
	mod.session.Set(USER, User{
		UserID:    user.GetID(),
		Username:  user.GetUsername(),
		FirstName: user.GetFirstName(),
		LastName:  user.GetLastName(),
	})
	err = mod.session.Save()
	return user, err
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

// DeactivateUser set inactive user as Deactived
func (mod *Module) DeactivatedUser(user UserModel) (UserModel, error) {
	if !user.GetIsActive() {
		return user, ErrAlreadyInactived
	}
	user.SetIsActive(false)
	return mod.repo.Update(user)
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

// UpdateSession replacing current sessions.Session in the module
func (mod *Module) UpdateSession(sess sessions.Session) {
	mod.session = sess
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
