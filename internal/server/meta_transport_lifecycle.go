package server

import (
	"maps"
	"reflect"
	"strconv"
)

func (server *Server) prepareMetaTransportLifecycle(
	previous,
	next *runtimeState,
) map[string]struct{} {
	retired := make(map[string]struct{})
	previousTargets := metaBackendTargetsByConfigKey(previous)
	for _, target := range previousTargets {
		server.observeMetaTransportGeneration(target.transportGeneration)
	}
	if next == nil {
		for _, target := range previousTargets {
			retired[metaBackendTransportOwner(target)] = struct{}{}
		}
		return retired
	}
	cloneMetaBackendTransportConfigurations(next)

	for databaseIndex := range next.databases {
		configuration := next.databases[databaseIndex].metaBackend
		if configuration == nil {
			continue
		}
		for targetIndex := range configuration.targets {
			target := &configuration.targets[targetIndex]
			previousTarget, found := previousTargets[target.configDNKey]
			if found && previousTarget.transportGeneration != 0 &&
				metaBackendTransportConfigurationEqual(previousTarget, *target) {
				target.transportGeneration = previousTarget.transportGeneration
			} else {
				target.transportGeneration = server.metaTransportSequence.Add(1)
			}
			if found {
				delete(previousTargets, target.configDNKey)
				if previousTarget.transportGeneration != target.transportGeneration {
					retired[metaBackendTransportOwner(previousTarget)] = struct{}{}
				}
			}
		}
	}
	for _, target := range previousTargets {
		retired[metaBackendTransportOwner(target)] = struct{}{}
	}
	return retired
}

func cloneMetaBackendTransportConfigurations(runtime *runtimeState) {
	if runtime == nil {
		return
	}
	runtime.databases = append([]runtimeDatabase(nil), runtime.databases...)
	for index := range runtime.databases {
		runtime.databases[index].metaBackend =
			runtime.databases[index].metaBackend.clone()
	}
}

func (server *Server) observeMetaTransportGeneration(generation uint64) {
	for {
		current := server.metaTransportSequence.Load()
		if generation <= current ||
			server.metaTransportSequence.CompareAndSwap(current, generation) {
			return
		}
	}
}

func metaBackendTargetsByConfigKey(
	runtime *runtimeState,
) map[string]metaBackendTargetRuntimeConfiguration {
	targets := make(map[string]metaBackendTargetRuntimeConfiguration)
	if runtime == nil {
		return targets
	}
	for databaseIndex := range runtime.databases {
		configuration := runtime.databases[databaseIndex].metaBackend
		if configuration == nil {
			continue
		}
		for _, target := range configuration.targets {
			targets[target.configDNKey] = target
		}
	}
	return targets
}

func metaBackendTransportOwners(runtime *runtimeState) map[string]struct{} {
	owners := make(map[string]struct{})
	for _, target := range metaBackendTargetsByConfigKey(runtime) {
		owners[metaBackendTransportOwner(target)] = struct{}{}
	}
	return owners
}

func metaBackendTransportConfigurationEqual(
	previous,
	next metaBackendTargetRuntimeConfiguration,
) bool {
	return previous.onlineURIUnavailable == next.onlineURIUnavailable &&
		reflect.DeepEqual(previous.ldapBackend, next.ldapBackend) &&
		metaBackendRWMTransportConfigurationEqual(previous.rwm, next.rwm)
}

func metaBackendRWMTransportConfigurationEqual(
	previous,
	next *rwmRuntimeConfiguration,
) bool {
	if previous == nil || next == nil {
		return previous == next
	}
	return metaBackendRWMSuffixEqual(previous.suffix, next.suffix) &&
		maps.Equal(previous.attributesToRemote, next.attributesToRemote) &&
		maps.Equal(previous.attributesToLocal, next.attributesToLocal) &&
		previous.attributesDropMissing == next.attributesDropMissing &&
		maps.Equal(previous.classesToRemote, next.classesToRemote) &&
		maps.Equal(previous.classesToLocal, next.classesToLocal) &&
		previous.classesDropMissing == next.classesDropMissing
}

func metaBackendRWMSuffixEqual(previous, next *rwmSuffixMapping) bool {
	if previous == nil || next == nil {
		return previous == next
	}
	return previous.local.Equal(next.local) && previous.remote.Equal(next.remote)
}

func metaBackendTransportOwner(
	target metaBackendTargetRuntimeConfiguration,
) string {
	return target.configDNKey + "\x00transport-generation=" +
		strconv.FormatUint(target.transportGeneration, 10)
}
