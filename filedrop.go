package main

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fmt"

	"github.com/carbocation/interpose"
	"github.com/gorilla/mux"
)

var conf config

type uploadResponse struct {
	URL     string
	Expires time.Time
}

type config struct {
	Adress       string
	Droplocation string
	Infolocation string
	URL          string
}

func (c *config) load(path string) error {
	body, err := ioutil.ReadFile(path + ".json")
	if err != nil {
		return err
	}
	err = json.Unmarshal(body, &c)
	return err
}

type fileinfo struct {
	Creator string
	Expires time.Time
}

func (f *fileinfo) save(name string) error {
	path := conf.Infolocation + "/files/" + name + ".json"
	j, err := json.MarshalIndent(&f, "", "    ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, j, 0644)
}

func (f *fileinfo) load(name string) error {
	path := conf.Infolocation + "/files/" + name + ".json"
	body, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	err = json.Unmarshal(body, &f)
	return err
}

type userinfo struct {
	Password string
}

func (u *userinfo) load(name string) error {
	path := conf.Infolocation + "/users/" + name + ".json"
	body, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	err = json.Unmarshal(body, &u)
	if err != nil {
		return err
	}
	return nil
}

func computeMd5(filePath string) (string, error) {
	var result string
	var res []byte
	file, err := os.Open(filePath)
	if err != nil {
		return result, err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return result, err
	}
	res = hash.Sum(nil)[:16]

	return hex.EncodeToString(res), nil
}

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

func getAuthorization(r *http.Request) (string, string, error) {
	auth := r.Header.Get("Authorization")
	s := strings.Split(auth, " ")
	if len(s) < 2 {
		return "", "", errors.New("Authorization header malformed. Expected \"Authorization token\" got " + auth)
	}
	return s[0], s[1], nil
}

func getUserfromRequest(r *http.Request) (string, string, error) {
	u, p := "", ""

	m, t, err := getAuthorization(r)
	if err != nil {
		log.Println("Error while getting Auth: ", err)
		return u, p, err
	}

	if strings.ToLower(m) != "basic" {
		log.Println("Error: identifier is not basic")
		return u, p, err
	}

	data, err := base64.StdEncoding.DecodeString(t)
	if err != nil {
		log.Println("Error decoding base64: ", err)
		return u, p, err
	}

	s := strings.Split(string(data), ":")
	if len(s) < 2 {
		log.Println("Error: slice to short")
		return u, p, err
	}

	u, p = s[0], s[1]
	return u, p, nil
}

func authMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			u, p, err := getUserfromRequest(r)
			if err != nil {
				http.Error(w, "Authentication failed", http.StatusUnauthorized)
				log.Println("Error getting User from Request: ", err)
				return
			}

			cont, err := exists(conf.Infolocation + "/users/" + u)

			if err != nil {
				http.Error(w, "Authentication failed", http.StatusUnauthorized)
				log.Println("Error checking file: ", err)
				return
			}

			if !cont {
				http.Error(w, "Authentication failed", http.StatusUnauthorized)
				log.Println("User does not exist")
				return
			}

			var ui userinfo

			err = ui.load(u)
			if err != nil {
				http.Error(w, "Authentication failed", http.StatusUnauthorized)
				log.Println("Error loading userinfo: ", err)
				return
			}

			if ui.Password != p {
				http.Error(w, "Authentication failed", http.StatusUnauthorized)
				log.Println("Password missmatch")
				return
			}

			next.ServeHTTP(w, r)

		})
	}
}

func uploadFileHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.Header.Get("Filename")
	xfilename := r.Header.Get("X-Filename")
	hash := r.Header.Get("X-File-MD5")

	if xfilename != "" {
		filename = xfilename
	}

	if filename == "" {
		http.Error(w, "Empty Filename given", http.StatusBadRequest)
		return
	}

	fn, err := base64.StdEncoding.DecodeString(filename)
	if err != nil {
		http.Error(w, "Error while decoding base64:"+err.Error(), http.StatusBadRequest)
		return
	}
	filename = strings.Replace(string(fn), " ", "_", -1)

	if len(filename) > 255 {
		http.Error(w, "Filename exceeds 255 Letters", http.StatusBadRequest)
		return
	}

	fp := filepath.FromSlash(conf.Droplocation + "/" + filename)

	cont := true
	it := 0

	for cont {
		cont, err = exists(fp)
		if err != nil {
			http.Error(w, "Authentication failed", http.StatusUnauthorized)
			log.Println("Error checking file: ", err)
			return
		}

		if cont {
			it++
			extension := filepath.Ext(filename)
			name := filename[0 : len(filename)-len(extension)]
			fp = filepath.FromSlash(conf.Droplocation + "/" + name + "_" + strconv.Itoa(it) + "." + extension)
		}
	}

	out, err := os.Create(fp) //Speicher file in uploaded
	if err != nil {           //Fehler beim abspeichern
		http.Error(w, "Error creating file:"+err.Error(), http.StatusInternalServerError)
		return
	}

	defer out.Close()

	// Kopiert den Content aus dem Request Body in eine Datei
	_, err = io.Copy(out, r.Body)
	if err != nil {
		http.Error(w, "Error copying file from response:"+err.Error(), http.StatusInternalServerError)
		return
	}

	if hash != "" {

		localhash, err := computeMd5(fp)
		if err != nil {
			http.Error(w, "Error creating hash:"+err.Error(), http.StatusInternalServerError)
		}

		h := string(localhash)

		if h != hash {
			http.Error(w, "Hash are not identical", http.StatusConflict)
			os.Remove(fp)
			return
		}
	}
	u, _, _ := getUserfromRequest(r)

	finof := fileinfo{u, time.Now().Add(time.Hour * 24 * 7)}
	name := filepath.Base(fp)
	err = finof.save(name)
	if err != nil {
		http.Error(w, "Error saving Infofile:"+err.Error(), http.StatusInternalServerError)
		os.Remove(fp)
		return
	}

	ur := uploadResponse{conf.URL + "/" + name, finof.Expires}
	j, err := json.Marshal(&ur)
	if err != nil {
		http.Error(w, "Error while json creation:"+err.Error(), http.StatusInternalServerError)
		os.Remove(fp)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(j)
}

func deleteFileHandler(w http.ResponseWriter, r *http.Request) {
}

func main() {
	conf.load("config")
	fmt.Println(conf)

	os.MkdirAll(filepath.FromSlash(conf.Infolocation+"/users/"), 0755)
	os.MkdirAll(filepath.FromSlash(conf.Infolocation+"/files/"), 0755)
	os.MkdirAll(filepath.FromSlash(conf.Droplocation), 0755)

	middle := interpose.New()
	middle.Use(authMiddleware())

	router := mux.NewRouter()
	router.HandleFunc("/", uploadFileHandler).Methods("POST")
	router.HandleFunc("/", deleteFileHandler).Methods("DELETE")

	log.Fatal(http.ListenAndServe(conf.Adress, middle))
}
