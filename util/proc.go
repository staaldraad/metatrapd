package util

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func convertToHex(ipport string) string {
	// split ip and port
	s := strings.Split(ipport, ":")
	// convert to net.IP so we don't have to worry about strconv.Atoi on each octet
	ip := net.ParseIP(s[0])
	// not the most correct way, but gives same result
	iphex := fmt.Sprintf("%02x%02x%02x%02x", ip[15], ip[14], ip[13], ip[12])
	port, _ := strconv.ParseInt(s[1], 10, 64)
	porthex := strconv.FormatInt(port, 16)

	return strings.ToUpper(iphex + ":" + porthex)
}

// cleanStatLine removes empty columns from the output of
// /proc/net/tcp - spaces are used as padding which leads
// to additional "columns". This fixes that
func cleanStatLine(line []string) []string {
	var cleanLine []string
	for _, i := range line {
		if i != "" {
			cleanLine = append(cleanLine, i)
		}
	}
	return cleanLine
}

// getConnectionInode takes a localAddr (addr:port) and
// parses /proc/net/tcp to retrieve the inode for the connection
func getConnectionInode(localAddr string) (string, error) {
	var inode string
	// convert ip:port to hex
	hexAddr := convertToHex(localAddr)

	// read /proc/net/tcp
	// use a scanner so we can do line by line and stop when match is found
	f, err := os.Open("/proc/net/tcp")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := scanner.Text()
		parts := cleanStatLine(strings.Split(strings.TrimSpace(line), " "))
		if parts[1] == hexAddr {
			inode = parts[9]
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	if inode == "" {
		return "", fmt.Errorf("no inode found")
	}

	return inode, nil
}

func findInodeOwner(inode string) (string, error) {
	sockinode := fmt.Sprintf("socket:[%s]", inode)
	sourcePid := ""

	// using filepath.Glob is more readable and the performance
	// difference between doing a Glob and WalkDir is near zero
	// this is more readable
	descriptors, err := filepath.Glob("/proc/[0-9]*/fd/[0-9]*")
	if err != nil {
		return "", err
	}

	for _, d := range descriptors {
		link, err := os.Readlink(d)
		if err != nil {
			continue
		}
		if link == sockinode {
			sourcePid = strings.Split(d, "/")[2]
			break
		}
	}
	if sourcePid == "" {
		return "unknown", fmt.Errorf("could not resolve exe path")
	}

	return sourcePid, nil
}

func getExePath(pid string) (string, error) {
	path := "/proc/" + pid + "/exe"
	return os.Readlink(path)
}

func ResolveConnectionOwner(localAddr string) (string, error) {
	// read the inode of the socket from /proc/net/tcp
	inode, err := getConnectionInode(localAddr)
	if err != nil {
		return "", err
	}

	// resolve the inode back to a pid
	pid, err := findInodeOwner(inode)
	if err != nil {
		return pid, err
	}

	// get the path of the executable of the pid
	exe, err := getExePath(pid)
	if err != nil {
		return "unknown", err
	}

	return exe, nil
}
