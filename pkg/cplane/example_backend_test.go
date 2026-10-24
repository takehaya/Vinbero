package cplane

import (
	"context"
	"os"
	"testing"

	"github.com/takehaya/vinbero/pkg/cplane/native"
	"github.com/takehaya/vinbero/pkg/cplane/wasm"
)

// The matrix reuses the same integration corpus and expected final maps.
// These tests are serial because the selector uses testing.T.Setenv.
func nativeExampleTests() bool {
	return os.Getenv("VINBERO_CPLANE_TEST_EXAMPLE_BACKEND") == BackendNative
}

func exampleManagerConfig(config ManagerConfig) ManagerConfig {
	config.AllowNative = nativeExampleTests()
	return config
}

func exampleRegistration(reg Registration) Registration {
	if nativeExampleTests() {
		reg.Module = nil
		reg.Backend, reg.NativeID, reg.NativeVersion = BackendNative, native.CustomBehavior, native.ImplementationVersion
	}
	return reg
}

func exampleInstantiate(ctx context.Context, config wasm.Config) (pluginInstance, error) {
	if nativeExampleTests() {
		config.Module = nil
		return native.Instantiate(ctx, native.Config{Config: config, Implementation: native.CustomBehavior, Version: native.ImplementationVersion})
	}
	return wasm.Instantiate(ctx, config)
}

func TestNativeCustomBehaviorIntegration(t *testing.T) {
	t.Setenv("VINBERO_CPLANE_TEST_EXAMPLE_BACKEND", BackendNative)
	for _, test := range []struct {
		name string
		run  func(*testing.T)
	}{
		{"steer", TestExamplePluginSteersItsOwnBehavior},
		{"withdraw", TestExamplePluginHandlesWithdrawWithoutAttributes},
		{"other behavior", TestExamplePluginIgnoresOtherBehaviors},
		{"complete set", TestExamplePluginDeclaresTheWholeSet},
		{"restart", TestExamplePluginConvergesAfterRestart},
		{"configured behavior", TestExamplePluginHonoursConfiguredBehavior},
		{"sender loop", TestExamplePluginCompletesTheLoop},
		{"unregister", TestExamplePluginUnregisterRetractsEverything},
		{"multiple paths", TestExamplePluginKeepsAPrefixWhileAnyPathRemains},
		{"replay", TestExamplePluginDropsItsViewOnReplay},
		{"disable sending", TestExamplePluginDisablingSendingRetractsPreviousOwnerState},
		{"dropped SID notification", TestExamplePluginRetriesDroppedSIDNotification},
		{"capability reduction", TestExamplePluginCapabilityReductionPrunesStateWithinUnchangedScope},
		{"withdrawal scope", TestExampleScopeAllowsWithdrawal},
		{"prefix filter", TestExampleReceivePrefixes},
		{"publication dependencies", TestExampleReplacementKeepsReferencedSIDsWhenPublicationFails},
	} {
		t.Run(test.name, test.run)
	}
}
