package server

import (
	"context"
	"errors"
	"testing"
	"time"
)

type seqmodTestAcquisition struct {
	name    string
	release func()
	err     error
}

func TestSeqmodCoordinatorSerializesSameKeyFIFO(t *testing.T) {
	t.Parallel()

	coordinator := newSeqmodCoordinator()
	releaseFirst, err := coordinator.acquire(context.Background(), "uid=alice,dc=example")
	if err != nil {
		t.Fatalf("acquire first: %v", err)
	}
	acquired := make(chan seqmodTestAcquisition, 2)
	for _, name := range []string{"second", "third"} {
		name := name
		go func() {
			release, err := coordinator.acquire(context.Background(), "uid=alice,dc=example")
			acquired <- seqmodTestAcquisition{name: name, release: release, err: err}
		}()
		waitForSeqmodQueueLength(t, coordinator, "uid=alice,dc=example", map[string]int{
			"second": 2,
			"third":  3,
		}[name])
	}

	select {
	case got := <-acquired:
		t.Fatalf("%s acquired before first release", got.name)
	default:
	}
	releaseFirst()
	second := receiveSeqmodAcquisition(t, acquired)
	if second.name != "second" || second.err != nil {
		t.Fatalf("second acquisition = %#v", second)
	}
	select {
	case got := <-acquired:
		t.Fatalf("%s acquired before second release", got.name)
	default:
	}
	second.release()
	third := receiveSeqmodAcquisition(t, acquired)
	if third.name != "third" || third.err != nil {
		t.Fatalf("third acquisition = %#v", third)
	}
	third.release()
	third.release()
	waitForSeqmodQueueLength(t, coordinator, "uid=alice,dc=example", 0)
}

func TestSeqmodCoordinatorAllowsDifferentKeys(t *testing.T) {
	t.Parallel()

	coordinator := newSeqmodCoordinator()
	releaseAlice, err := coordinator.acquire(context.Background(), "uid=alice,dc=example")
	if err != nil {
		t.Fatalf("acquire Alice: %v", err)
	}
	defer releaseAlice()
	releaseBob, err := coordinator.acquire(context.Background(), "uid=bob,dc=example")
	if err != nil {
		t.Fatalf("acquire Bob: %v", err)
	}
	releaseBob()
}

func TestSeqmodCoordinatorRemovesCanceledWaiter(t *testing.T) {
	t.Parallel()

	coordinator := newSeqmodCoordinator()
	key := "uid=alice,dc=example"
	releaseFirst, err := coordinator.acquire(context.Background(), key)
	if err != nil {
		t.Fatalf("acquire first: %v", err)
	}

	secondContext, cancelSecond := context.WithCancel(context.Background())
	secondDone := make(chan error, 1)
	go func() {
		_, err := coordinator.acquire(secondContext, key)
		secondDone <- err
	}()
	waitForSeqmodQueueLength(t, coordinator, key, 2)

	thirdAcquired := make(chan func(), 1)
	go func() {
		release, err := coordinator.acquire(context.Background(), key)
		if err != nil {
			thirdAcquired <- nil
			return
		}
		thirdAcquired <- release
	}()
	waitForSeqmodQueueLength(t, coordinator, key, 3)

	cancelSecond()
	if err := <-secondDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter error = %v", err)
	}
	waitForSeqmodQueueLength(t, coordinator, key, 2)
	releaseFirst()
	select {
	case release := <-thirdAcquired:
		if release == nil {
			t.Fatal("third acquisition failed")
		}
		release()
	case <-time.After(2 * time.Second):
		t.Fatal("third waiter was not promoted")
	}
}

func receiveSeqmodAcquisition(
	t *testing.T,
	acquired <-chan seqmodTestAcquisition,
) seqmodTestAcquisition {
	t.Helper()
	select {
	case result := <-acquired:
		return result
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for seqmod acquisition")
		return seqmodTestAcquisition{}
	}
}

func waitForSeqmodQueueLength(
	t *testing.T,
	coordinator *seqmodCoordinator,
	key string,
	want int,
) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		coordinator.mu.Lock()
		got := len(coordinator.queues[key])
		coordinator.mu.Unlock()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("queue length = %d, want %d", got, want)
		}
		time.Sleep(time.Millisecond)
	}
}
