test_universal_charms() {
	if [ "$(skip 'test_universal_charms')" ]; then
		echo "==> TEST SKIPPED: universal charms tests"
		return
	fi

	set_verbosity

	echo "==> Checking for dependencies"
	check_dependencies juju

	file="${TEST_DIR}/test-universal-charms.log"
	bootstrap "test-universal-charms" "${file}"

	test_deploy_formatv2_on_iaas
	test_formatv1_still_works

	case "${BOOTSTRAP_PROVIDER:-}" in
	"k8s")
		test_formatv2_on_k8s_unchanged
		;;
	*)
		echo "==> TEST SKIPPED: test_formatv2_on_k8s_unchanged - not a k8s provider"
		;;
	esac

	destroy_controller "test-universal-charms"
}

test_deploy_formatv2_on_iaas() {
	if [ -n "$(skip 'test_deploy_formatv2_on_iaas')" ]; then
		echo "==> SKIP: Asked to skip deploy FormatV2 on IAAS"
		return
	fi

	case "${BOOTSTRAP_PROVIDER:-}" in
	"k8s")
		echo "==> TEST SKIPPED: test_deploy_formatv2_on_iaas - k8s provider"
		return
		;;
	esac

	model_name="universal-charms-iaas"
	file="${TEST_DIR}/test-${model_name}.log"
	ensure "${model_name}" "${file}"

	juju deploy juju-qa-pebble-checks
	wait_for "juju-qa-pebble-checks" "$(idle_condition "juju-qa-pebble-checks")" 900

	# The pebble-ready hook should have run once the IAAS workload container
	# created its pebble socket and PebblePoller observed it.
	timeout 2m juju debug-log --replay --no-tail | grep -m 1 "ubuntu-pebble-ready"

	# Hooks execute on the unit agent host, but pebble is reachable via the
	# workload socket exposed under the unit data directory.
	juju exec --unit juju-qa-pebble-checks/0 -- pebble services

	destroy_model "${model_name}"
}

test_formatv1_still_works() {
	if [ -n "$(skip 'test_formatv1_still_works')" ]; then
		echo "==> SKIP: Asked to skip FormatV1 IAAS regression"
		return
	fi

	case "${BOOTSTRAP_PROVIDER:-}" in
	"k8s")
		echo "==> TEST SKIPPED: test_formatv1_still_works - k8s provider"
		return
		;;
	esac

	model_name="universal-charms-formatv1"
	file="${TEST_DIR}/test-${model_name}.log"
	ensure "${model_name}" "${file}"

	juju deploy ubuntu-lite
	wait_for "ubuntu-lite" "$(idle_condition "ubuntu-lite")" 900

	destroy_model "${model_name}"
}

test_formatv2_on_k8s_unchanged() {
	if [ -n "$(skip 'test_formatv2_on_k8s_unchanged')" ]; then
		echo "==> SKIP: Asked to skip FormatV2 K8s regression"
		return
	fi

	model_name="universal-charms-k8s"
	file="${TEST_DIR}/test-${model_name}.log"
	ensure "${model_name}" "${file}"

	juju deploy juju-qa-pebble-checks
	wait_for "juju-qa-pebble-checks" "$(idle_condition "juju-qa-pebble-checks")" 900

	destroy_model "${model_name}"
}
