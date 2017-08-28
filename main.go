package main

import (
    "bufio"
    "database/sql"
    "encoding/json"
    "fmt"
    "log"
    "io"
    "net/http"
    "os"
    "os/exec"
    "os/signal"
    "strconv"
    "strings"
    "sync"
    "syscall"
    "time"

    _ "github.com/mattn/go-sqlite3"
    "github.com/urfave/negroni"
)

var port = ":3000"

var db *sql.DB
var dbMutex sync.Mutex

func statsHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Access-Control-Allow-Origin", "*")

    switch r.Method {
    case "GET":
        dbMutex.Lock()
        defer dbMutex.Unlock()

        stmt, err := db.Prepare("select total(len) from packet where created_at >= ? and created_at < ?")
        if err != nil {
            log.Println(err)
            w.WriteHeader(http.StatusInternalServerError)
            return
        }
        defer stmt.Close()

        ls := []float64{}
        tstr := r.FormValue("date")
        t, err := time.Parse("2006-01-02", tstr)
        if err != nil {
            log.Println(err)
            w.WriteHeader(http.StatusInternalServerError)
            return
        }

        year := t.Year()
        month := t.Month()
        day := t.Day()
        for i := 0; i < 24; i++ {
            var l float64
            ta := time.Date(year, month, day, i, 0, 0, 0, time.UTC)
            tb := time.Date(year, month, day, i + 1, 0, 0, 0, time.UTC)
            if err := stmt.QueryRow(ta, tb).Scan(&l); err != nil {
                log.Println(err)
                w.WriteHeader(http.StatusInternalServerError)
                return
            }

            ls = append(ls, l)
        }

        data, err := json.Marshal(ls)
        if err != nil {
            log.Println(err)
            w.WriteHeader(http.StatusInternalServerError)
            return
        }

        w.Write(data)
    default:
        w.WriteHeader(http.StatusMethodNotAllowed)
    }
}

func save(srcIp string, srcPort int, dstIp string, dstPort int, nBytes int) error {
    dbMutex.Lock()
    defer dbMutex.Unlock()

    t := time.Now()
    _, err := db.Exec(`insert into packet(src_ip, src_port, dst_ip, dst_port, len, created_at) values(?, ?, ?, ?, ?, ?)`, srcIp, srcPort, dstIp, dstPort, nBytes, t)
    if err != nil {
        return err
    }

    return nil
}

func main() {
    // Get arguments or environment variable settings
    if tmp := os.Getenv("PORT"); tmp != "" {
        port = ":" + tmp
    }

    // Open database
    tmpDb, err := sql.Open("sqlite3", "netlog.db")
    if err != nil {
        log.Fatal(err)
    }
    db = tmpDb

    // Create table
    stmtStr := `create table packet(
        id integer not null primary key,
        src_ip text not null,
        src_port integer not null,
        dst_ip text not null,
        dst_port integer not null,
        len integer not null,
        created_at datetime not null
    )`
    _, err = db.Exec(stmtStr)
    if err != nil && err.Error() != "table packet already exists" {
        log.Fatal(err)
    }

    // Prepare tcpdump command
    cmd := exec.Command("tcpdump", "-an", "portrange", "1-65535")

    // Handle signal
    sigchan := make(chan os.Signal, 1)
    signal.Notify(sigchan, os.Interrupt, syscall.SIGTERM)
    go func() {
        var s string
        switch <-sigchan {
        case os.Interrupt:
            s = "interrupt"
        case syscall.SIGTERM:
            s = "terminate"
        }
        fmt.Println("Received signal:", s)
        cmd.Process.Kill()
        os.Exit(0)
    }()

    // Start server
    mux := http.NewServeMux()
    mux.HandleFunc("/stats", statsHandler)
    n := negroni.Classic()
    n.UseHandler(mux)
    go func() {
        log.Println("Listening at", port)
        http.ListenAndServe(port, n)
    }()

    // Get tcpdump stdout
    output, err := cmd.StdoutPipe()
    if err != nil {
        log.Fatal(err)
    }

    // Start tcpdump
    err = cmd.Start()
    if err != nil {
        output.Close()
        log.Fatal(err)
    }

    // Parse tcpdump output
    s := bufio.NewScanner(output)
    go func(output io.ReadCloser) {
        for s.Scan() {
            line := s.Text()
            words := strings.Split(line, " ")
            nBytesStr := words[len(words)-1]

            // Parse source IP address
            if len(words) <= 2 {
                continue
            }
            src := strings.Split(words[2], ".")
            if len(src) < 5 {
                continue
            }
            srcIp := strings.Join(src[:4], ".")
            srcPort, err := strconv.Atoi(src[4])
            if err != nil {
                continue
            }

            // Parse destination IP address
            if len(words) <= 4 {
                continue
            }
            dst := strings.Split(words[4][:len(words[4])-1], ".")
            if len(dst) < 5 {
                continue
            }
            dstIp := strings.Join(dst[:4], ".")
            dstPort, err := strconv.Atoi(dst[4])
            if err != nil {
                continue
            }

            // Convert number of bytes transferred if applicable
            nBytes, err := strconv.Atoi(nBytesStr);
            if err != nil || nBytes <= 0 {
                continue
            }

            err = save(srcIp, srcPort, dstIp, dstPort, nBytes)
            if err != nil {
                log.Fatal(err)
            }
        }
    }(output)

    // Wait for command to finish
    cmd.Wait()
    os.Exit(0)
}
