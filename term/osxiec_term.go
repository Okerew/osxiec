package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/creack/pty"
)

type Tab struct {
	id   int
	cmd  *exec.Cmd
	pty  *os.File
	done chan bool
}

var (
	tabs     = make(map[int]*Tab)
	nextID   = 1
	tabsLock sync.Mutex
	activeID = -1
)

func createTab() int {
	tabsLock.Lock()
	defer tabsLock.Unlock()

	cmd := exec.Command("bash")
	ptmx, err := pty.Start(cmd)
	if err != nil {
		fmt.Println("Error creating tab:", err)
		return -1
	}

	id := nextID
	nextID++

	done := make(chan bool)
	tabs[id] = &Tab{
		id:   id,
		cmd:  cmd,
		pty:  ptmx,
		done: done,
	}

	go func() {
		io.Copy(os.Stdout, ptmx)
		close(done)
	}()

	if activeID == -1 {
		activeID = id
	}

	return id
}

func sendCommand(id int, command string) {
	tabsLock.Lock()
	tab, exists := tabs[id]
	tabsLock.Unlock()

	if !exists {
		fmt.Printf("Tab %d does not exist\n", id)
		return
	}

	_, err := tab.pty.Write([]byte(command + "\n"))
	if err != nil {
		fmt.Printf("Error sending command to tab %d: %v\n", id, err)
		return
	}
}

func listTabs() {
	tabsLock.Lock()
	defer tabsLock.Unlock()

	fmt.Println("Active tabs:")
	for id := range tabs {
		if id == activeID {
			fmt.Printf("* %d (active)\n", id)
		} else {
			fmt.Printf("  %d\n", id)
		}
	}
}

func switchTab(id int) {
	tabsLock.Lock()
	defer tabsLock.Unlock()

	if _, exists := tabs[id]; !exists {
		fmt.Printf("Tab %d does not exist\n", id)
		return
	}

	activeID = id
	fmt.Printf("Switched to tab %d\n", id)
}

func closeTab(id int) {
	tabsLock.Lock()
	tab, exists := tabs[id]
	if !exists {
		tabsLock.Unlock()
		fmt.Printf("Tab %d does not exist\n", id)
		return
	}
	delete(tabs, id)
	tabsLock.Unlock()

	tab.cmd.Process.Signal(syscall.SIGTERM)
	<-tab.done
	tab.pty.Close()

	if activeID == id {
		if len(tabs) > 0 {
			for newID := range tabs {
				activeID = newID
				break
			}
		} else {
			activeID = -1
		}
	}

	fmt.Printf("Closed tab %d\n", id)
}

func main() {
	print("Okral Terminal v0.1\n")
	scanner := bufio.NewScanner(os.Stdin)

	for {
		if activeID != -1 {
			fmt.Printf("[Tab %d]> ", activeID)
		} else {
			fmt.Print("> ")
		}
		scanner.Scan()
		input := scanner.Text()

		if input == "bye" {
			break
		}

		switch {
		case input == "new":
			id := createTab()
			fmt.Printf("Created new tab with ID: %d\n", id)
		case strings.HasPrefix(input, "switch "):
			parts := strings.SplitN(input, " ", 2)
			if len(parts) != 2 {
				fmt.Println("Usage: switch <tab_id>")
				continue
			}
			id, err := strconv.Atoi(parts[1])
			if err != nil {
				fmt.Println("Invalid tab ID")
				continue
			}
			switchTab(id)
		case input == "list":
			listTabs()
		case strings.HasPrefix(input, "close "):
			parts := strings.SplitN(input, " ", 2)
			if len(parts) != 2 {
				fmt.Println("Usage: close <tab_id>")
				continue
			}
			id, err := strconv.Atoi(parts[1])
			if err != nil {
				fmt.Println("Invalid tab ID")
				continue
			}
			closeTab(id)
		case strings.HasPrefix(input, "send "):
			parts := strings.SplitN(input, " ", 3)
			if len(parts) < 3 {
				fmt.Println("Usage: send <tab_id> <command>")
				continue
			}
			id, err := strconv.Atoi(parts[1])
			if err != nil {
				fmt.Println("Invalid tab ID")
				continue
			}
			sendCommand(id, parts[2])
		default:
			if activeID != -1 {
				sendCommand(activeID, input)
			} else {
				fmt.Println("No active tab. Available commands: new, switch <tab_id>, list, close <tab_id>, send <tab_id> <command>, bye")
			}
		}
	}

	// Clean up tabs
	for _, tab := range tabs {
		tab.cmd.Process.Signal(syscall.SIGTERM)
		<-tab.done
		tab.pty.Close()
	}
}
