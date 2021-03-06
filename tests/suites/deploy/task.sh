test_deploy() {
    if [ "$(skip 'test_deploy')" ]; then
        echo "==> TEST SKIPPED: CMR bundle tests"
        return
    fi

    set_verbosity

    echo "==> Checking for dependencies"
    check_dependencies juju

    file="${TEST_DIR}/test-cmr-bundles.txt"

    bootstrap "test-cmr-bundles" "${file}"

    test_deploy_charms
    test_deploy_bundles
    test_cmr_bundles_export_overlay

    destroy_controller "test-cmr-bundles"
}
