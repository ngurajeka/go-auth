package auth

import (
	"encoding/gob"
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/gin-contrib/sessions"
	db "upper.io/db.v3"
	"upper.io/db.v3/lib/sqlbuilder"
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

// Module for Authentication
type Module struct {
	db      sqlbuilder.Database
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
func New(db sqlbuilder.Database) Module {
	return Module{db: db}
}

// UpdateSession replacing current sessions.Session in the module
func (mod *Module) UpdateSession(sess sessions.Session) {
	mod.session = sess
}

// CreateNewUser storing new user data into repository
func (mod *Module) CreateNewUser(data UserModel) (UserModel, error) {
	// check username exist
	if total, _ := mod.db.Collection(data.TableName()).
		Find(db.Cond{"username": data.GetUsername()}).Count(); total != 0 {
		return data, ErrUserDuplicate
	}
	// making sure user is not active and created time is utc.now
	data.SetIsActive(StatusInactive)
	data.SetCreatedTime(time.Now().UTC())
	// storing data
	if _, err := mod.db.Collection(data.TableName()).
		Insert(&data); err != nil {
		return data, err
	}
	return data, nil
}

// Authenticate verify username and password is match with bcrypt Encryption
func (mod *Module) Authenticate(data UserModel, password string) (UserModel, error) {
	// check username exist and active
	if err := mod.db.Collection(data.TableName()).
		Find(db.Cond{"username": data.GetUsername(), "deleted_at": nil}).
		One(&data); err != nil {
		if err == db.ErrNoMoreRows {
			return data, ErrNotFound
		}
		return data, err
	}
	if !data.GetIsActive() {
		return data, ErrInactive
	}
	// compare []byte(password) and []byte(user.Password) data
	if err := bcrypt.CompareHashAndPassword(data.GetPassword(), []byte(password)); err != nil {
		return data, ErrMissmatch
	}
	// storing into session
	mod.session.Set(USER, User{
		UserID:    data.GetID(),
		Username:  data.GetUsername(),
		FirstName: data.GetFirstName(),
		LastName:  data.GetLastName(),
	})
	err := mod.session.Save()
	return data, err
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
