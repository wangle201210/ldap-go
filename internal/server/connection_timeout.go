package server

import (
	"context"
	"net"
	"sync/atomic"
	"time"
)

const (
	disabledIdleTimeoutPoll = time.Second
	minimumIdleTimeoutPoll  = 50 * time.Millisecond
	maximumIdleTimeoutPoll  = time.Second
)

type connectionActivity struct {
	lastRead atomic.Int64
}

func newConnectionActivity() *connectionActivity {
	activity := &connectionActivity{}
	activity.observeRead(time.Now())
	return activity
}

func (activity *connectionActivity) observeRead(now time.Time) {
	if activity == nil {
		return
	}
	activity.lastRead.Store(now.UnixNano())
}

func (activity *connectionActivity) lastReadTime() time.Time {
	if activity == nil {
		return time.Time{}
	}
	value := activity.lastRead.Load()
	if value == 0 {
		return time.Time{}
	}
	return time.Unix(0, value)
}

func (activity *connectionActivity) expired(
	timeout time.Duration,
	now time.Time,
) bool {
	if activity == nil || timeout <= 0 {
		return false
	}
	last := activity.lastReadTime()
	return !last.IsZero() && now.After(last.Add(timeout))
}

type activityTrackingConnection struct {
	net.Conn
	activity *connectionActivity
}

func (connection *activityTrackingConnection) Read(value []byte) (int, error) {
	count, err := connection.Conn.Read(value)
	if count > 0 {
		connection.activity.observeRead(time.Now())
	}
	return count, err
}

func (server *Server) currentConnectionIdleTimeout() time.Duration {
	runtime := server.runtime.Load()
	if runtime == nil {
		return 0
	}
	return runtime.idleTimeout
}

func (server *Server) currentConnectionWriteTimeout() time.Duration {
	runtime := server.runtime.Load()
	if runtime == nil {
		return 0
	}
	return runtime.writeTimeout
}

func (server *Server) watchConnectionIdleTimeout(
	ctx context.Context,
	cancel context.CancelFunc,
	connection net.Conn,
	activity *connectionActivity,
	operations *operationRegistry,
) {
	timer := time.NewTimer(idleTimeoutCheckDelay(
		server.currentConnectionIdleTimeout(),
		activity,
		time.Now(),
	))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-timer.C:
			timeout := server.currentConnectionIdleTimeout()
			if timeout > 0 && operations.closeIfIdle(
				activity,
				timeout,
				now,
				func() {
					cancel()
					_ = connection.Close()
				},
			) {
				return
			}
			timer.Reset(idleTimeoutCheckDelay(timeout, activity, now))
		}
	}
}

func idleTimeoutCheckDelay(
	timeout time.Duration,
	activity *connectionActivity,
	now time.Time,
) time.Duration {
	if timeout <= 0 {
		return disabledIdleTimeoutPoll
	}
	delay := timeout / 4
	if delay < minimumIdleTimeoutPoll {
		delay = minimumIdleTimeoutPoll
	}
	if delay > maximumIdleTimeoutPoll {
		delay = maximumIdleTimeoutPoll
	}
	if activity != nil {
		remaining := activity.lastReadTime().Add(timeout).Sub(now)
		if remaining > 0 && remaining < delay {
			delay = remaining
		}
	}
	return delay
}
