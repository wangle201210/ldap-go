package server

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
)

type syncConsumerManager struct {
	server *Server

	mu      sync.Mutex
	desired []syncConsumerConfig
	running bool
	cancel  context.CancelFunc
	wake    chan struct{}
	done    chan struct{}
}

type syncConsumerWorker struct {
	config syncConsumerConfig
	cancel context.CancelFunc
	done   chan struct{}
}

func newSyncConsumerManager(server *Server) *syncConsumerManager {
	return &syncConsumerManager{server: server}
}

func (manager *syncConsumerManager) configure(runtime *runtimeState) {
	desired := activeSyncConsumerConfigs(runtime)

	manager.mu.Lock()
	manager.desired = desired
	if manager.running {
		select {
		case manager.wake <- struct{}{}:
		default:
		}
	}
	manager.mu.Unlock()
}

func (manager *syncConsumerManager) start(parent context.Context) error {
	manager.mu.Lock()
	if manager.running {
		manager.mu.Unlock()
		return errors.New("server is already serving")
	}
	ctx, cancel := context.WithCancel(parent)
	manager.running = true
	manager.cancel = cancel
	manager.wake = make(chan struct{}, 1)
	manager.done = make(chan struct{})
	wake := manager.wake
	done := manager.done
	manager.mu.Unlock()

	go manager.run(ctx, wake, done)
	return nil
}

func (manager *syncConsumerManager) stop() {
	manager.mu.Lock()
	if !manager.running {
		manager.mu.Unlock()
		return
	}
	cancel := manager.cancel
	done := manager.done
	manager.mu.Unlock()

	cancel()
	<-done

	manager.mu.Lock()
	if manager.done == done {
		manager.running = false
		manager.cancel = nil
		manager.wake = nil
		manager.done = nil
	}
	manager.mu.Unlock()
}

func (manager *syncConsumerManager) run(
	ctx context.Context,
	wake <-chan struct{},
	done chan<- struct{},
) {
	defer close(done)
	workers := make(map[string]*syncConsumerWorker)

	for {
		if !manager.reconcile(ctx, workers) {
			manager.stopWorkers(workers)
			return
		}
		select {
		case <-ctx.Done():
			manager.stopWorkers(workers)
			return
		case <-wake:
		}
	}
}

func (manager *syncConsumerManager) reconcile(
	ctx context.Context,
	workers map[string]*syncConsumerWorker,
) bool {
	desired := manager.snapshot()
	desiredByKey := make(map[string]syncConsumerConfig, len(desired))
	for _, config := range desired {
		desiredByKey[syncConsumerWorkerKey(config)] = config
	}

	for key, worker := range workers {
		config, keep := desiredByKey[key]
		if keep && reflect.DeepEqual(worker.config, config) {
			delete(desiredByKey, key)
			continue
		}
		worker.cancel()
		select {
		case <-worker.done:
			delete(workers, key)
		case <-ctx.Done():
			return false
		}
	}

	for key, config := range desiredByKey {
		workerContext, cancel := context.WithCancel(ctx)
		worker := &syncConsumerWorker{
			config: config,
			cancel: cancel,
			done:   make(chan struct{}),
		}
		workers[key] = worker
		go func() {
			defer close(worker.done)
			manager.server.runSyncConsumer(workerContext, worker.config)
		}()
	}
	return true
}

func (manager *syncConsumerManager) stopWorkers(
	workers map[string]*syncConsumerWorker,
) {
	for _, worker := range workers {
		worker.cancel()
	}
	for key, worker := range workers {
		<-worker.done
		delete(workers, key)
	}
}

func (manager *syncConsumerManager) snapshot() []syncConsumerConfig {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return append([]syncConsumerConfig(nil), manager.desired...)
}

func activeSyncConsumerConfigs(runtime *runtimeState) []syncConsumerConfig {
	if runtime == nil {
		return nil
	}
	var configs []syncConsumerConfig
	for _, database := range runtime.databases {
		if database.disabled {
			continue
		}
		configs = append(configs, database.syncConsumers...)
	}
	return configs
}

func syncConsumerWorkerKey(config syncConsumerConfig) string {
	return fmt.Sprintf("%s\x00%03d", config.partition, config.rid)
}
