//go:build !linux

package dataplane

import "context"

type Runtime struct{}

func Load(_ Config) (*Runtime, error) {
	return nil, ErrUnsupportedPlatform
}

func (*Runtime) ConfigureClient(ClientSettings) error {
	return ErrUnsupportedPlatform
}

func (*Runtime) ConfigureServer(ServerSettings) error {
	return ErrUnsupportedPlatform
}

func (*Runtime) RegisterPath(RegistrationSettings) error {
	return ErrUnsupportedPlatform
}

func (*Runtime) RevokeRegistration(ClientKey) error {
	return ErrUnsupportedPlatform
}

func (*Runtime) UpdatePathState(uint8, uint32) error {
	return ErrUnsupportedPlatform
}

func (*Runtime) Sweep(uint64) error {
	return ErrUnsupportedPlatform
}

func (*Runtime) Snapshot() (StatsSnapshot, error) {
	return StatsSnapshot{}, ErrUnsupportedPlatform
}

func (*Runtime) ConsumeEvents(context.Context, func(Event)) error {
	return ErrUnsupportedPlatform
}

func (*Runtime) AttachClient([]int) error {
	return ErrUnsupportedPlatform
}

func (*Runtime) AttachServer([]int) error {
	return ErrUnsupportedPlatform
}

func (*Runtime) SetPath(int, PathSettings) error {
	return ErrUnsupportedPlatform
}

func (*Runtime) ClearPath(int) error {
	return ErrUnsupportedPlatform
}

func (*Runtime) SetGroup(GroupSettings) error {
	return ErrUnsupportedPlatform
}

func (*Runtime) ClientRoutes() ([]ClientRoute, error) {
	return nil, ErrUnsupportedPlatform
}

func (*Runtime) ServerRoutes() ([]ServerRoute, error) {
	return nil, ErrUnsupportedPlatform
}

func (*Runtime) Registrations() ([]Registration, error) {
	return nil, ErrUnsupportedPlatform
}

func (*Runtime) RegisteredPaths() ([]RegisteredPath, error) {
	return nil, ErrUnsupportedPlatform
}

func (*Runtime) Close() error {
	return nil
}
