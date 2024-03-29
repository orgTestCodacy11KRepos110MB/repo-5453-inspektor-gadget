include $(shell pwd)/../../../minikube.mk

# make does not allow implicit rules (with '%') to be phony so let's use
# the 'phony_explicit' dependency to make implicit rules inherit the phony
# attribute
.PHONY: phony_explicit
phony_explicit:


# build

build:
	make -C $(shell pwd)/../../.. local-gadget

.PHONY: build-tests
build-tests:
	docker buildx build -t local-gadget-tests -f ./../../../Dockerfiles/local-gadget-tests.Dockerfile ../../../
	docker run --rm --entrypoint cat local-gadget-tests local-gadget-integration.test > ./local-gadget-integration.test

# test

TEST_TARGETS = \
	test-docker \
	test-containerd \
	test-cri-o

.PHONY: test-all
test-all: $(TEST_TARGETS) test

test: test-$(CONTAINER_RUNTIME)

# INTEGRATION_TESTS_PARAMS can be used to pass additional parameters locally e.g
# INTEGRATION_TESTS_PARAMS="-test.run TestListContainers" CONTAINER_RUNTIME=containerd make -C integration/local-gadget/k8s test
.PHONY: phony_explicit
test-%: build build-tests
	export MINIKUBE_PROFILE=minikube-$* && \
	echo "Checking minikube with profile $${MINIKUBE_PROFILE} is running ..." && \
	$(MINIKUBE) status -p $${MINIKUBE_PROFILE} -f {{.APIServer}} >/dev/null || (echo "Error: $${MINIKUBE_PROFILE} not running, exiting ..." && exit 1) && \
	echo "Preparing minikube with profile $${MINIKUBE_PROFILE} for testing ..." && \
	$(MINIKUBE) cp ../../../local-gadget-linux-amd64 $${MINIKUBE_PROFILE}:/bin/local-gadget >/dev/null && \
	$(MINIKUBE) ssh sudo chmod +x /bin/local-gadget && \
	$(MINIKUBE) cp local-gadget-integration.test $${MINIKUBE_PROFILE}:/bin/local-gadget-integration.test >/dev/null && \
	$(MINIKUBE) ssh sudo chmod +x /bin/local-gadget-integration.test && \
	rm local-gadget-integration.test && \
	$(MINIKUBE) -p $${MINIKUBE_PROFILE} ssh "sudo ln -sf /var/lib/minikube/binaries/$(KUBERNETES_VERSION)/kubectl /bin/kubectl" && \
	$(MINIKUBE) -p $${MINIKUBE_PROFILE} ssh "sudo ln -sf /etc/kubernetes/admin.conf /root/.kube/config" && \
	echo "Running test in minikube with profile $${MINIKUBE_PROFILE} ..." && \
	$(MINIKUBE) -p $${MINIKUBE_PROFILE} ssh "sudo local-gadget-integration.test -test.v -integration -container-runtime $* $${INTEGRATION_TESTS_PARAMS}"
