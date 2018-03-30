package main

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/go-sql-driver/mysql"
)

func main() {
	dconf, err := dbConfFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	d, err := newDB(dconf)
	if err != nil {
		log.Fatal(err)
	}

	uu, err := d.Users()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("before add:")
	for _, u := range uu {
		fmt.Println(u)
	}

	if err := d.AddUser("jerry"); err != nil {
		log.Fatal(err)
	}
	uu, err = d.Users()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("after add:")
	for _, u := range uu {
		fmt.Println(u)
	}

	if err := d.UpdateUser("jerry", "Jerry"); err != nil {
		log.Fatal(err)
	}
	uu, err = d.Users()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("after update:")
	for _, u := range uu {
		fmt.Println(u)
	}

	if err := d.DelUser("Jerry"); err != nil {
		log.Fatal(err)
	}
	uu, err = d.Users()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("after delete:")
	for _, u := range uu {
		fmt.Println(u)
	}
}

var (
	errCertPath       = errors.New("DB_CA_CERT_PATH is required and was not set")
	errClientCertPath = errors.New("DB_CLIENT_CERT_PATH is required and was not set")
	errClientKeyPath  = errors.New("DB_CLIENT_KEY_PATH is required and was not set")
	errCertPEM        = errors.New("trusted conn with DB not established, cannot parse cert PEM")
)

func dbConfFromEnv() (*mysql.Config, error) {
	dconf := &mysql.Config{
		User:      "root",
		Passwd:    "",
		Net:       "tcp",
		Addr:      "localhost:3306",
		DBName:    "mycrud",
		Loc:       time.UTC,
		ParseTime: true,
	}
	if v, ok := os.LookupEnv("DB_USER"); ok {
		dconf.User = v
	}
	if v, ok := os.LookupEnv("DB_PASS"); ok {
		dconf.Passwd = v
	}
	if v, ok := os.LookupEnv("DB_ADDR"); ok {
		dconf.Addr = v
	}
	if v, ok := os.LookupEnv("DB_NAME"); ok {
		dconf.DBName = v
	}
	if _, ok := os.LookupEnv("DB_SKIP_TLS"); ok {
		return dconf, nil
	}
	caCertPath, ok := os.LookupEnv("DB_CA_CERT_PATH")
	if !ok {
		return nil, errCertPath
	}
	clientCertPath, ok := os.LookupEnv("DB_CLIENT_CERT_PATH")
	if !ok {
		return nil, errClientCertPath
	}
	clientKeyPath, ok := os.LookupEnv("DB_CLIENT_KEY_PATH")
	if !ok {
		return nil, errClientKeyPath
	}
	tconf, err := tlsConfig(caCertPath, clientCertPath, clientKeyPath)
	if err != nil {
		return nil, err
	}
	dconf.TLSConfig = tconf
	return dconf, nil
}

// tlsConfig calls mysql driver to enable TLS for mysql connection. tconfKey is
// a key to retrieve the specific tls.Config created by tlsConfig.  It should
// be used in the db connection string as the value of the tls param.  Use
// caCertPath to specify the trusted certificates for the database. Use
// clientCertPath and clientKeyPath to specify the client certificate and key
// to be used for the db connection.
func tlsConfig(caCertPath, clientCertPath, clientKeyPath string) (tconfKey string, err error) {
	pem, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		return "", err
	}
	rootCertPool := x509.NewCertPool()
	if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
		return "", errCertPEM
	}
	cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return "", err
	}
	dbTLSConfig := &tls.Config{
		RootCAs:      rootCertPool,
		Certificates: []tls.Certificate{cert},
	}
	tconfKey = "custom"
	if err := mysql.RegisterTLSConfig(tconfKey, dbTLSConfig); err != nil {
		return "", err
	}
	return tconfKey, nil
}

type db struct {
	db *sql.DB
}

func newDB(dconf *mysql.Config) (*db, error) {
	d, err := sql.Open("mysql", dconf.FormatDSN())
	if err != nil {
		return nil, fmt.Errorf("newDB Open: %v", err)
	}
	if err := d.Ping(); err != nil {
		return nil, fmt.Errorf("newDB Ping: %v", err)
	}
	return &db{db: d}, nil
}

type user struct {
	id        string
	createdAt time.Time
	updatedAt time.Time
	name      string
}

func (u *user) String() string {
	return fmt.Sprintf("[ ID: %s, CreatedAt: %s, UpdatedAt: %s, Name: %q ]",
		u.id,
		u.createdAt.UTC().Format(time.RFC3339),
		u.updatedAt.UTC().Format(time.RFC3339),
		u.name,
	)
}

func (db *db) Users() ([]*user, error) {
	q := `select id,cat,uat,name from user`
	rows, err := db.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var uu []*user
	for rows.Next() {
		u := user{}
		if err := rows.Scan(&u.id, &u.createdAt, &u.updatedAt, &u.name); err != nil {
			return nil, err
		}
		uu = append(uu, &u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return uu, nil
}

func (db *db) AddUser(name string) error {
	q := `insert into user(name) values(?)`
	_, err := db.db.Exec(q, name)
	return err
}

func (db *db) DelUser(name string) error {
	q := `delete from user where name=?`
	_, err := db.db.Exec(q, name)
	return err
}

func (db *db) UpdateUser(oldname, newname string) error {
	q := `update user set name=? where name=?`
	_, err := db.db.Exec(q, newname, oldname)
	return err
}

/* user table

create table user (
	id char(128),
	cat timestamp default current_timestamp,
	uat timestamp default current_timestamp on update current_timestamp,
	name varchar(128)
	unique (name)
)

delimiter //
create trigger init_uuid before insert on user
  for each row set new.id = uuid();
//
delimiter ;

*/
