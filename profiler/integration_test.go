// Copyright 2017 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build integration

package profiler

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"testing"
	"text/template"
	"time"

	"cloud.google.com/go/storage"
	"golang.org/x/build/kubernetes"
	kubernetesAPI "golang.org/x/build/kubernetes/api"
	"golang.org/x/build/kubernetes/gke"
	"golang.org/x/net/context"
	"golang.org/x/oauth2/google"
	cloudbuild "google.golang.org/api/cloudbuild/v1"
	compute "google.golang.org/api/compute/v1"
	container "google.golang.org/api/container/v1"
	"google.golang.org/api/googleapi"
)

var (
	zone       = flag.String("zone", "us-west1-a", "test resources zone")
	projectID  = flag.String("project_id", "dulcet-port-762", "test project ID")
	bucketName = flag.String("bucket_name", "dulcet-port-762-go-cloud-profiler-test", "GCS bucket used to store transient data")
	commit     = flag.String("commit", "HEAD", "Git on Borg commit to test")

	timeStamp = time.Now().Unix()
)

const (
	cloudScope           = "https://www.googleapis.com/auth/cloud-platform"
	monitorWriteScope    = "https://www.googleapis.com/auth/monitoring.write"
	storageReadScope     = "https://www.googleapis.com/auth/devstorage.read_only"
	expectedFunctionName = "busywork"
	benchFinishString    = "busybench finished profiling"
)

const startupTemplate = `
#! /bin/bash

set -x

# Install git
sudo apt-get update
sudo apt-get -y -q install git-all

# Install desired Go version
mkdir -p /tmp/bin
curl -sL -o /tmp/bin/gimme https://raw.githubusercontent.com/travis-ci/gimme/master/gimme
chmod +x /tmp/bin/gimme
export PATH=$PATH:/tmp/bin

eval "$(gimme {{.GoVersion}})"

# Set $GOPATH
export GOPATH="$HOME/go"

export GOCLOUD_HOME=$GOPATH/src/cloud.google.com/go
mkdir -p $GOCLOUD_HOME

# Install agent
git clone https://code.googlesource.com/gocloud $GOCLOUD_HOME

# TODO: remove when merge
git checkout profiler-test

cd $GOCLOUD_HOME
git reset --hard {{.Commit}}
go get -v ./...

# Run benchmark with agent
go test -v cloud.google.com/go/profiler -timeout=15m -tags=busybench -target="{{.Target}}" -run TestBusy

# Indicate script finished
echo {{.FinishString}}
`

const dockerfileFmt = `FROM golang
RUN git clone https://code.googlesource.com/gocloud /go/src/cloud.google.com/go
RUN cd /go/src/cloud.google.com/go && git checkout profiler-test && git reset --hard %v
RUN go get -v cloud.google.com/go/...
CMD go test -v cloud.google.com/go/profiler -timeout=15m -tags=busybench -target="%v" -finish_string="%v" -run TestBusy
 `

type testRunner struct {
	client           *http.Client
	startupTemplate  *template.Template
	containerService *container.Service
	computeService   *compute.Service
	storageClient    *storage.Client
}

type profileResponse struct {
	Profile     profileData   `json:"profile"`
	NumProfiles int32         `json:"numProfiles"`
	Deployments []interface{} `json:"deployments"`
}

type profileData struct {
	Samples           []int32       `json:"samples"`
	SampleMetrics     interface{}   `json:"sampleMetrics"`
	DefaultMetricType string        `json:"defaultMetricType"`
	TreeNodes         interface{}   `json:"treeNodes"`
	Functions         functionArray `json:"functions"`
	SourceFiles       interface{}   `json:"sourceFiles"`
}

type functionArray struct {
	Name       []string `json:"name"`
	Sourcefile []int32  `json:"sourceFile"`
}

func checkSymbolization(pr profileResponse) error {
	if pr.Profile.Functions.Name == nil {
		return fmt.Errorf("profile has no function name")
	}
	for _, name := range pr.Profile.Functions.Name {
		if strings.Contains(name, expectedFunctionName) {
			return nil
		}
	}
	return fmt.Errorf("expected function name %v not found in profile", expectedFunctionName)
}

func validateProfile(rawData []byte) error {
	var pr profileResponse
	if err := json.Unmarshal(rawData, &pr); err != nil {
		return err
	}

	if pr.NumProfiles == 0 {
		return fmt.Errorf("profile response contains 0 profile: %v", pr)
	}

	if len(pr.Deployments) == 0 {
		return fmt.Errorf("profile response contains 0 deployment: %v", pr)
	}

	if err := checkSymbolization(pr); err != nil {
		return fmt.Errorf("checkSymbolization failed with %v for %v", err, pr)
	}
	return nil
}

type instanceConfig struct {
	name      string
	target    string
	goVersion string
}

func getTestInstances() []instanceConfig {
	return []instanceConfig{
		{
			name:      fmt.Sprintf("profiler-test-go19-%v", timeStamp),
			target:    fmt.Sprintf("profiler-test-go19-%v-gce", timeStamp),
			goVersion: "1.9",
		},
		{
			name:      fmt.Sprintf("profiler-test-go18-%v", timeStamp),
			target:    fmt.Sprintf("profiler-test-go18-%v-gce", timeStamp),
			goVersion: "1.8",
		},
		{
			name:      fmt.Sprintf("profiler-test-go17-%v", timeStamp),
			target:    fmt.Sprintf("profiler-test-go17-%v-gce", timeStamp),
			goVersion: "1.7",
		},
		{
			name:      fmt.Sprintf("profiler-test-go16-%v", timeStamp),
			target:    fmt.Sprintf("profiler-test-go16-%v-gce", timeStamp),
			goVersion: "1.6",
		},
	}
}

type gkeConfig struct {
	clusterName     string
	podName         string
	imageSourceName string
	imageName       string
	target          string
}

func getGKEConfig() gkeConfig {
	return gkeConfig{
		clusterName:     fmt.Sprintf("profiler-test-cluster-%v", timeStamp),
		podName:         fmt.Sprintf("profiler-test-pod-%v", timeStamp),
		imageSourceName: fmt.Sprintf("profiler-test/%v/Dockerfile.zip", timeStamp),
		imageName:       fmt.Sprintf("%v/profiler-test-%v", *projectID, timeStamp),
		target:          fmt.Sprintf("profiler-test-%v-gke", timeStamp),
	}
}

func renderStartupScript(template *template.Template, inst instanceConfig) (string, error) {
	var buf bytes.Buffer
	err := template.Execute(&buf,
		struct {
			Target       string
			FinishString string
			GoVersion    string
			Commit       string
		}{
			Target:       inst.target,
			FinishString: benchFinishString,
			GoVersion:    inst.goVersion,
			Commit:       *commit,
		})
	if err != nil {
		return "", fmt.Errorf("failed to render startup script for %v: %v", inst.name, err)
	}

	return buf.String(), nil
}

func (tr *testRunner) startInstance(ctx context.Context, inst instanceConfig) error {
	img, err := tr.computeService.Images.GetFromFamily("debian-cloud", "debian-9").Context(ctx).Do()
	if err != nil {
		return err
	}

	startupScript, err := renderStartupScript(tr.startupTemplate, inst)
	if err != nil {
		return err
	}

	_, err = tr.computeService.Instances.Insert(*projectID, *zone, &compute.Instance{
		MachineType: fmt.Sprintf("zones/%s/machineTypes/n1-standard-1", *zone),
		Name:        inst.name,
		Disks: []*compute.AttachedDisk{{
			AutoDelete: true, // delete the disk when the VM is deleted.
			Boot:       true,
			Type:       "PERSISTENT",
			Mode:       "READ_WRITE",
			DeviceName: "testDisk",
			InitializeParams: &compute.AttachedDiskInitializeParams{
				SourceImage: img.SelfLink,
				DiskType:    fmt.Sprintf("https://www.googleapis.com/compute/v1/projects/%s/zones/%s/diskTypes/pd-standard", *projectID, *zone),
			},
		}},
		NetworkInterfaces: []*compute.NetworkInterface{{
			Network: fmt.Sprintf("https://www.googleapis.com/compute/v1/projects/%s/global/networks/default", *projectID),
			AccessConfigs: []*compute.AccessConfig{{
				Name: "External NAT",
			}},
		}},
		Metadata: &compute.Metadata{
			Items: []*compute.MetadataItems{{
				Key:   "startup-script",
				Value: googleapi.String(startupScript),
			}},
		},
		ServiceAccounts: []*compute.ServiceAccount{{
			Email: "default",
			Scopes: []string{
				monitorWriteScope,
				storageReadScope,
			},
		}},
	}).Do()

	return err
}

func (tr *testRunner) deleteInstance(ctx context.Context, inst instanceConfig, t *testing.T) {
	_, err := tr.computeService.Instances.Delete(*projectID, *zone, inst.name).Context(ctx).Do()
	if err != nil {
		t.Errorf("failed to delete instance %v: %v", inst.name, err)
	}
}

func (tr *testRunner) pollForSerialOutput(ctx context.Context, projectID, zone, instanceName string) error {
	var output string
	defer func() {
		log.Printf("serial port output for %v:\n%v", instanceName, output)
	}()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for startup: %q", instanceName)

		case <-time.After(20 * time.Second):
			resp, err := tr.computeService.Instances.GetSerialPortOutput(projectID, zone, instanceName).Context(ctx).Do()
			if err != nil {
				// Transient failure.
				log.Printf("Transient error getting serial port output %q: %v (will retry)", instanceName, err)
				continue
			}

			if output = resp.Contents; strings.Contains(output, benchFinishString) {
				return nil
			}
		}
	}
}

func (tr *testRunner) queryAndCheckProfile(target, startTime, endTime, profileType string) error {
	queryURL := fmt.Sprintf("https://cloudprofiler.googleapis.com/v2/projects/%s/profiles:query", *projectID)
	queryRequest := fmt.Sprintf(`{"deploymentLabels": {},"endTime": "%s","profileLabels": {},"profileType": "%s","startTime": "%s","target": "%s"}`,
		endTime, profileType, startTime, target)

	resp, err := tr.client.Post(queryURL, "application/json", strings.NewReader(queryRequest))
	if err != nil {
		return fmt.Errorf("failed to query API: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	if err := validateProfile(body); err != nil {
		return fmt.Errorf("failed to validate profile %v", err)
	}

	return nil
}

func (tr *testRunner) runTestOnGCE(ctx context.Context, inst instanceConfig, t *testing.T) {
	defer func() {
		tr.deleteInstance(ctx, inst, t)
	}()

	err := tr.startInstance(ctx, inst)
	if err != nil {
		t.Fatalf("failed to start instance %v: %v", inst.name, err)
	}

	timeoutContext, cancel := context.WithTimeout(ctx, time.Minute*20)
	defer cancel()
	if err := tr.pollForSerialOutput(timeoutContext, *projectID, *zone, inst.name); err != nil {
		t.Fatalf("failed to wait for script complete %v: %v", inst.name, err)
	}

	endTime := time.Now()
	startTime := endTime.Add(-1 * time.Hour)

	if err := tr.queryAndCheckProfile(inst.target, startTime.Format(time.RFC3339), endTime.Format(time.RFC3339), "CPU"); err != nil {
		t.Errorf("failed to query and check profile %v/CPU: %v", inst.name, err)
	}

	if err := tr.queryAndCheckProfile(inst.target, startTime.Format(time.RFC3339), endTime.Format(time.RFC3339), "HEAP"); err != nil {
		t.Errorf("failed to query and check profile %v/HEAP: %v", inst.name, err)
	}
}

// createGKEImage creates a docker image from source code in a GCS bucket
// and push the image to Google Container Registry.
func (tr *testRunner) createGKEImage(ctx context.Context, projectID, sourceBucket, sourceObject, targetImage string) error {
	cloudbuildService, err := cloudbuild.New(tr.client)

	build := &cloudbuild.Build{
		Source: &cloudbuild.Source{
			StorageSource: &cloudbuild.StorageSource{
				Bucket: sourceBucket,
				Object: sourceObject,
			},
		},
		Steps: []*cloudbuild.BuildStep{
			{
				Name: "gcr.io/cloud-builders/docker",
				Args: []string{"build", "-t", targetImage, "."},
			},
		},
		Images: []string{targetImage},
	}

	op, err := cloudbuildService.Projects.Builds.Create(projectID, build).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to create image: %v", err)
	}
	operationId := op.Name

	// wait for creating image
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting creating image")

		case <-time.After(10 * time.Second):
			op, err := cloudbuildService.Operations.Get(operationId).Context(ctx).Do()
			if err != nil {
				log.Printf("transient error getting operation (will retry): %v", err)
				break
			}
			if op.Done == true {
				log.Print("created GKE image")
				return nil
			}
		}
	}
}

type imageResponse struct {
	Manifest map[string]interface{} `json:"manifest"`
	Name     string                 `json:"name"`
	Tags     []string               `json:"tags"`
}

// deleteGKEImage deletes an image from Google Container Registry.
func (tr *testRunner) deleteGKEImage(ctx context.Context, imageName string, t *testing.T) {
	queryImageURL := fmt.Sprintf("https://gcr.io/v2/%v/tags/list", imageName)
	resp, err := tr.client.Get(queryImageURL)
	if err != nil {
		t.Errorf("Get(%v) got error: %v", queryImageURL, err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("ioutil.ReadAll(resp.Body) got error: %v", err)
		return
	}
	var ir imageResponse
	if err := json.Unmarshal(body, &ir); err != nil {
		t.Errorf("json.Unmarshal() got error: %v", err)
		return
	}

	deleteImageURLFmt := "https://gcr.io/v2/%v/manifests/%v"
	for _, tag := range ir.Tags {
		if err := deleteGKEImageResource(tr.client, fmt.Sprintf(deleteImageURLFmt, imageName, tag)); err != nil {
			t.Errorf("deleteGKEImageResource(%v:tag:%v) got error: %v", imageName, tag, err)
		}
	}

	for manifest := range ir.Manifest {
		if err := deleteGKEImageResource(tr.client, fmt.Sprintf(deleteImageURLFmt, imageName, manifest)); err != nil {
			t.Errorf("deleteGKEImageResource(%v:manifest:%v) got error: %v", imageName, manifest, err)
		}
	}
}

func deleteGKEImageResource(client *http.Client, url string) error {
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to get reqeust: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete resource: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("delete resource status code: %v", resp.StatusCode)
	}
	return nil
}

func (tr *testRunner) createCluster(ctx context.Context, client *http.Client, projectID, zone, clusterName string) error {
	request := &container.CreateClusterRequest{Cluster: &container.Cluster{
		Name:             clusterName,
		InitialNodeCount: 1,
		NodeConfig: &container.NodeConfig{
			OauthScopes: []string{
				storageReadScope,
			},
		},
	}}
	op, err := tr.containerService.Projects.Zones.Clusters.Create(projectID, zone, request).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to create cluster, %v", err)
	}
	operationId := op.Name

	// wait for creating cluster.
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting creating cluster")

		case <-time.After(10 * time.Second):
			op, err := tr.containerService.Projects.Zones.Operations.Get(projectID, zone, operationId).Context(ctx).Do()
			if err != nil {
				log.Printf("transient error getting operation (will retry): %v", err)
				break
			}
			if op.Status == "DONE" {
				log.Print("created cluster")
				return nil
			}
		}
	}
}

func (tr *testRunner) deleteCluster(ctx context.Context, projectID, zone, clusterID string, t *testing.T) {
	_, err := tr.containerService.Projects.Zones.Clusters.Delete(projectID, zone, clusterID).Context(ctx).Do()
	if err != nil {
		t.Errorf("deleteCluster(%v) got error: %v", clusterID, err)
	}
}

func (tr *testRunner) deployContainer(ctx context.Context, kubernetesClient *kubernetes.Client, podName, imageName string) error {
	pod := &kubernetesAPI.Pod{
		ObjectMeta: kubernetesAPI.ObjectMeta{
			Name: podName,
		},
		Spec: kubernetesAPI.PodSpec{
			RestartPolicy: kubernetesAPI.RestartPolicyNever,
			Containers: []kubernetesAPI.Container{
				{
					Name:  "profiler-test",
					Image: fmt.Sprintf("gcr.io/%v:latest", imageName),
				},
			},
		},
	}
	_, err := kubernetesClient.RunLongLivedPod(ctx, pod)
	if err != nil {
		return fmt.Errorf("failed to run pod, %v", err)
	}
	return nil
}

func (tr *testRunner) pollPodLog(ctx context.Context, kubernetesClient *kubernetes.Client, podName string) error {
	var output string
	defer func() {
		log.Printf("pod log:\n%v", output)
	}()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting GKE job finishing")

		case <-time.After(20 * time.Second):
			var err error
			output, err = kubernetesClient.PodLog(ctx, podName)
			if err != nil {
				// Transient failure.
				log.Printf("Transient error getting log: %v (will retry)", err)
				continue
			}
			if strings.Contains(output, benchFinishString) {
				return nil
			}
		}
	}
}

func (tr *testRunner) runTestOnGKE(ctx context.Context, t *testing.T, cfg gkeConfig) {
	defer func() {
		tr.deleteImageSource(ctx, *bucketName, cfg.imageSourceName, t)
		tr.deleteGKEImage(ctx, cfg.imageName, t)
		tr.deleteCluster(ctx, *projectID, *zone, cfg.clusterName, t)
	}()

	if err := tr.uploadImageSource(ctx, *bucketName, cfg.imageSourceName, *commit, cfg.target, benchFinishString); err != nil {
		t.Fatalf("uploadImageSource() got error: %v", err)
	}

	createImageCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := tr.createGKEImage(createImageCtx, *projectID, *bucketName, cfg.imageSourceName, fmt.Sprintf("gcr.io/%v", cfg.imageName)); err != nil {
		t.Fatalf("createGKEImage(%v) got error: %v", cfg.imageName, err)
	}

	createClusterCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := tr.createCluster(createClusterCtx, tr.client, *projectID, *zone, cfg.clusterName); err != nil {
		t.Fatalf("createCluster(%v) got error: %v", cfg.clusterName, err)
	}

	kubernetesClient, err := gke.NewClient(ctx, cfg.clusterName, gke.OptZone(*zone), gke.OptProject(*projectID))
	if err != nil {
		t.Fatalf("gke.NewClient() got error: %v", err)
	}

	deployContainerCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := tr.deployContainer(deployContainerCtx, kubernetesClient, cfg.podName, cfg.imageName); err != nil {
		t.Fatalf("deployContainer(%v, %v) got error: %v", cfg.podName, cfg.imageName, err)
	}

	pollLogCtx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	if err := tr.pollPodLog(pollLogCtx, kubernetesClient, cfg.podName); err != nil {
		t.Fatalf("pollPodLog(%v) got error: %v", cfg.podName, err)
	}

	endTime := time.Now()
	startTime := endTime.Add(-1 * time.Hour)

	if err := tr.queryAndCheckProfile(cfg.target, startTime.Format(time.RFC3339), endTime.Format(time.RFC3339), "CPU"); err != nil {
		t.Errorf("failed to query and check profile %v/CPU: %v\n", cfg.target, err)
	}

	if err := tr.queryAndCheckProfile(cfg.target, startTime.Format(time.RFC3339), endTime.Format(time.RFC3339), "HEAP"); err != nil {
		t.Errorf("failed to query and check profile %v/HEAP: %v\n", cfg.target, err)
	}

}

// uploadImageSource uploads source code for building docker image to GCS.
func (tr *testRunner) uploadImageSource(ctx context.Context, bucketName, objectName, commit, target, finishString string) error {
	zipBuf := new(bytes.Buffer)
	z := zip.NewWriter(zipBuf)
	f, err := z.Create("Dockerfile")
	if err != nil {
		return err
	}

	dockerfile := fmt.Sprintf(dockerfileFmt, commit, target, finishString)
	if _, err := f.Write([]byte(dockerfile)); err != nil {
		return err
	}

	if err := z.Close(); err != nil {
		return err
	}
	wc := tr.storageClient.Bucket(bucketName).Object(objectName).NewWriter(ctx)
	wc.ContentType = "application/zip"
	wc.ACL = []storage.ACLRule{{storage.AllUsers, storage.RoleReader}}
	if _, err := wc.Write(zipBuf.Bytes()); err != nil {
		return err
	}
	return wc.Close()
}

// deleteImageSource deletes image source code from GCS.
func (tr *testRunner) deleteImageSource(ctx context.Context, bucketName, objectName string, t *testing.T) {
	if err := tr.storageClient.Bucket(bucketName).Object(objectName).Delete(ctx); err != nil {
		t.Errorf("failed to delete image source %v/%v: %v", bucketName, objectName, err)
	}
}

func TestAgentIntegration(t *testing.T) {
	ctx := context.Background()

	client, err := google.DefaultClient(ctx, cloudScope)
	if err != nil {
		t.Fatalf("failed to get default client, %v", err)
	}

	storageClient, err := storage.NewClient(ctx)
	if err != nil {
		t.Fatalf("storage.NewClient() error: %v", err)
	}

	computeService, err := compute.New(client)
	if err != nil {
		t.Fatalf("failed to initialize compute service: %v", err)
	}

	containerService, err := container.New(client)
	if err != nil {
		fmt.Printf("failed to create container client, %v", err)
	}

	template, err := template.New("startupScript").Parse(startupTemplate)
	if err != nil {
		t.Fatalf("failed to parse startup script template: %v", err)
	}
	tr := testRunner{
		computeService:   computeService,
		client:           client,
		startupTemplate:  template,
		containerService: containerService,
		storageClient:    storageClient,
	}

	gkeCfg := getGKEConfig()
	t.Run(gkeCfg.target, func(t *testing.T) {
		t.Parallel()
		tr.runTestOnGKE(ctx, t, gkeCfg)
	})

	instances := getTestInstances()
	for _, instance := range instances {
		inst := instance // capture range variable
		t.Run(inst.target, func(t *testing.T) {
			t.Parallel()
			tr.runTestOnGCE(ctx, inst, t)
		})
	}

}
