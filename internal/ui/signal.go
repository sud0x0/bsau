package ui

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
)

// SignalHandler manages graceful shutdown on CTRL+C
type SignalHandler struct {
	ctx        context.Context
	cancel     context.CancelFunc
	prompter   *Prompter
	mu         sync.Mutex
	inProgress bool
	prompting  bool // true when signal handler is prompting user
	cleanupFn  func()
}

// NewSignalHandler creates a new signal handler
func NewSignalHandler() *SignalHandler {
	ctx, cancel := context.WithCancel(context.Background())
	return &SignalHandler{
		ctx:      ctx,
		cancel:   cancel,
		prompter: NewPrompter(),
	}
}

// SetCleanup sets a cleanup function to call on shutdown
func (s *SignalHandler) SetCleanup(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupFn = fn
}

// SetInProgress marks that work is in progress (affects prompt message)
func (s *SignalHandler) SetInProgress(inProgress bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inProgress = inProgress
}

// IsPrompting returns true if the signal handler is currently prompting the user
// Progress output should check this and skip printing if true
func (s *SignalHandler) IsPrompting() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.prompting
}

// Context returns the context that will be canceled on shutdown
func (s *SignalHandler) Context() context.Context {
	return s.ctx
}

// Start begins listening for interrupt signals
func (s *SignalHandler) Start() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		for {
			select {
			case <-s.ctx.Done():
				return
			case sig := <-sigChan:
				s.handleSignal(sig)
			}
		}
	}()
}

func (s *SignalHandler) handleSignal(sig os.Signal) {
	s.mu.Lock()
	inProgress := s.inProgress
	cleanupFn := s.cleanupFn
	s.prompting = true // Stop progress output
	s.mu.Unlock()

	// Clear any progress line and move to new line after ^C
	fmt.Print("\r\033[K\n")

	if inProgress {
		// Ask user if they really want to exit
		fmt.Printf("%s[INTERRUPT]%s Received %s signal\n", ColorYellow, ColorReset, sig)
		fmt.Println()

		// Use a simple prompt since we might be in raw mode
		fmt.Print("Exit now? This may leave temp files behind. [y/N]: ")

		reader := bufio.NewReader(os.Stdin)
		input, err := reader.ReadString('\n')
		if err != nil {
			// Error reading, just exit
			s.shutdown(cleanupFn)
			return
		}

		input = strings.TrimSpace(strings.ToLower(input))
		if input == "y" || input == "yes" {
			s.shutdown(cleanupFn)
		} else {
			s.mu.Lock()
			s.prompting = false // Resume progress output
			s.mu.Unlock()
			fmt.Printf("%s[INFO]%s Continuing...\n", ColorCyan, ColorReset)
		}
	} else {
		// Not in critical section, just exit
		s.shutdown(cleanupFn)
	}
}

func (s *SignalHandler) shutdown(cleanupFn func()) {
	fmt.Printf("%s[INFO]%s Shutting down gracefully...\n", ColorCyan, ColorReset)

	if cleanupFn != nil {
		cleanupFn()
	}

	s.cancel()
	os.Exit(130) // 128 + SIGINT(2) = 130
}

// Stop stops the signal handler
func (s *SignalHandler) Stop() {
	signal.Reset(os.Interrupt, syscall.SIGTERM)
	s.cancel()
}
