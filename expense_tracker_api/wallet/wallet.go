package wallet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"main/env"
	"main/models"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

var (
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrInvalidDecrypted  = errors.New("invalid encrypted data")
	ErrUserNotFound      = errors.New("user not found")
	ErrInvalidPassword   = errors.New("invalid password")
)

type User struct {
	ID       int    `json:"-"`
	Username string `json:"username"`
	Password string `json:"password"`
	Refresh  string `json:"-"`
}

type Balance struct {
	ID     int     `json:"-"`
	UserID int     `json:"userid"`
	Amount float32 `json:"Amount,omitempty"`
}

type Transaction struct {
	ID     int     `json:"-"`
	UserID int     `json:"-"`
	Amount float32 `json:"money"`
	Type   string  `json:"type"`
	Date   string  `json:"-"`
	Note   string  `json:"note,omitempty"`
	Tag    string  `json:"tag,omitempty"`
}

type Tlist struct {
	Income  []Transaction `json:"income,omitempty"`
	Outcome []Transaction `json:"outcome,omitempty"`
}

type File struct {
	Db   *sql.DB
	Path string
}

func (u *User) HashingPass() error {
	passHash, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.Password = string(passHash)
	return nil

}

func (u *User) CheckPass(passHash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(passHash), []byte(u.Password))
	if err != nil {
		return err
	}
	return nil
}

func (u *User) encryptRefresh() error {
	key, err := getAESKey()
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	cipherText := aesGCM.Seal(nil, nonce, []byte(u.Refresh), nil)
	u.Refresh = base64.StdEncoding.EncodeToString(append(nonce, cipherText...))
	return nil
}

func (u *User) decryptRefresh() error {
	key, err := getAESKey()
	if err != nil {
		return err
	}
	data, err := base64.StdEncoding.DecodeString(u.Refresh)
	if err != nil {
		return err
	}
	if len(data) < 12+aes.BlockSize { // aes.BlockSize == 16
		return ErrInvalidDecrypted
	}
	nonce, cipherText := data[:12], data[12:]
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	plainText, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return err
	}
	u.Refresh = string(plainText)
	return nil
}

func New(path string) (*File, error) {
	f := &File{Path: path}
	if err := f.Open(); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *File) Open() error {
	db, err := sql.Open("sqlite", f.Path)
	if err != nil {
		return err
	}
	f.Db = db
	return nil
}

func (f *File) Close() error {
	if f.Db != nil {
		return f.Db.Close()
	}
	return nil
}

func (f *File) AddBalance(b Balance) error {
	_, err := f.Db.Exec("INSERT INTO balance (user_id, amount) VALUES (:user_id,:amount);",
		sql.Named("user_id", b.UserID),
		sql.Named("amount", b.Amount))
	if err != nil {
		return err
	}
	return nil
}

func (f *File) MakeTable() error {
	_, err := f.Db.Exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, refresh_token TEXT NOT NULL);")
	if err != nil {
		return err
	}
	_, err = f.Db.Exec("CREATE TABLE IF NOT EXISTS balance (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, amount DECIMAL(10, 2) NOT NULL DEFAULT 0, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE);")
	if err != nil {
		return err
	}
	_, err = f.Db.Exec("CREATE TABLE IF NOT EXISTS transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, amount DECIMAL(10, 2) NOT NULL, type TEXT CHECK( type IN ('income', 'outcome') ) NOT NULL, date TEXT, note TEXT, tag TEXT, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE );")
	if err != nil {
		return err
	}
	return nil
}

func (f *File) AddUser(u User, b Balance) error {
	err := u.encryptRefresh()
	if err != nil {
		return err
	}
	err = u.HashingPass()
	if err != nil {
		return err
	}
	u.ID = -1
	new_user, err := f.Db.Exec("INSERT INTO users (username, password_hash,refresh_token) VALUES (:username, :password_hash, :refresh_token);",
		sql.Named("username", u.Username),
		sql.Named("password_hash", u.Password),
		sql.Named("refresh_token", u.Refresh))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return ErrUserAlreadyExists
		}
		return err
	}
	id, err := new_user.LastInsertId()
	if err != nil {
		panic(err)
	}
	u.ID = int(id)
	err = f.AddBalance(b)
	if err != nil {
		return err
	}
	return nil
}

func (f *File) Balance(id int) (float64, error) {
	row := f.Db.QueryRow("SELECT amount FROM balance WHERE user_id = :user_id;", sql.Named("user_id", id))
	var ammount float64
	err := row.Scan(&ammount)
	if err != nil {
		return 0, err
	}
	return ammount, nil
}
func (f *File) NewTransactions(t Transaction) error {
	_, err := f.Db.Exec("INSERT INTO transactions (user_id, amount, type, note, date, tag) VALUES (:user_id, :amount, :type, :note, :date, :tag);",
		sql.Named("user_id", t.UserID),
		sql.Named("amount", t.Amount),
		sql.Named("date", time.Now().Format("02.01.2006 15:04:05")),
		sql.Named("note", t.Note),
		sql.Named("tag", t.Tag),
		sql.Named("type", t.Type))
	if err != nil {
		return err
	}
	b := Balance{
		UserID: t.UserID,
		Amount: t.Amount,
	}
	err = f.UpdateBalance(b, t.Type)
	if err != nil {
		return err
	}
	return nil
}

func (f *File) UpdateBalance(b Balance, t string) error {
	var operation string
	switch t {
	case "outcome":
		operation = "-"
	case "income":
		operation = "+"
	}
	_, err := f.Db.Exec("UPDATE balance SET amount = amount "+operation+" :amount WHERE user_id = :user_id;",
		sql.Named("user_id", b.UserID),
		sql.Named("amount", b.Amount))
	if err != nil {
		return err
	}
	return nil
}

func (f *File) UpdateRefreshToken(u User) error {
	err := u.encryptRefresh()
	if err != nil {
		return err
	}
	_, err = f.Db.Exec("UPDATE users SET refresh_token = :refresh_token WHERE id = :id;",
		sql.Named("id", u.ID),
		sql.Named("refresh_token", u.Refresh))
	if err != nil {
		return err
	}
	return nil
}

func (f *File) Transactions(id int) (Tlist, error) {
	row, err := f.Db.Query("SELECT amount, type, date, note, tag FROM transactions WHERE user_id = :user_id;",
		sql.Named("user_id", id))
	if err != nil {
		return Tlist{}, err
	}
	var res Tlist
	for row.Next() {
		t := Transaction{}
		err := row.Scan(&t.Amount, &t.Type, &t.Date, &t.Note, &t.Tag)
		if err != nil {
			panic(err)
		}
		if t.Type == "outcome" {
			res.Outcome = append(res.Outcome, t)
		} else {
			res.Income = append(res.Income, t)
		}

	}
	return res, nil

}

// IsUserExists returns true if user with given auth data does not exist, false - if exists.
// If user does not exist, second return value is empty User, third - nil error.
// If user exists, second return value is User with filled ID, third - nil error.
// If error occurs (for example, if database connection is lost), second return value is empty User,
// third - error.
func (f *File) IsUserExists(a models.Auth) (bool, User, error) {
	u := User{Username: a.Username, Password: a.Password}
	row := f.Db.QueryRow("SELECT id, username,password_hash,refresh_token FROM users WHERE username = :username;",
		sql.Named("username", u.Username))
	var pass string
	err := row.Scan(&u.ID, &u.Username, &pass, &u.Refresh)
	if err != nil {
		if err == sql.ErrNoRows {
			return true, u, nil
		}
		return false, u, err
	}
	err = u.CheckPass(pass)
	if err != nil {
		return false, u, ErrInvalidPassword
	}
	err = u.decryptRefresh()
	if err != nil {
		return false, u, err
	}
	return false, u, nil
}

func (f *File) GetUser(username string) (User, error) {
	u := User{}
	row := f.Db.QueryRow("SELECT id, username,password_hash,refresh_token FROM users WHERE username = :username;",
		sql.Named("username", username))
	err := row.Scan(&u.ID, &u.Username, &u.Password, &u.Refresh)
	if err != nil {
		return u, err
	}
	err = u.decryptRefresh()
	if err != nil {
		return u, err
	}
	return u, nil
}

func getAESKey() ([]byte, error) {
	env := env.FromENV{}
	err := env.SetEnv()
	if err != nil {
		return nil, err
	}
	return []byte(env.SecretForAES), nil
}
