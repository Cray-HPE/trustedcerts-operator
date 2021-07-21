/*


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
TODO:
	- Consider webhook for polymorphic config validation (migrate JSON Schema validation)
	- Add status updates
	- Deal with multiple CRs targeting same destinations
	- How to deal with updates of source material outside CR modification
	- Add log logic to print out certificate properties
	- cross namespace ownership of configmaps (no ownership binding right now)
	- Finalizers to clean up config maps (perhaps not by default)
*/

package controllers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"reflect"

	"github.com/go-logr/logr"
	"github.com/qri-io/jsonschema"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	// "k8s.io/apimachinery/pkg/util/validation"
	"net/http"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	//"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	certificateshpecomv1alpha1 "github.com/Cray-HPE/trustedcerts-operator/internal/api/v1alpha1"
)

// TrustedCertificatesReconciler reconciles a TrustedCertificates object
type TrustedCertificatesReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// CACerts - For storage of ca-certs cloud-init update
type CACerts struct {
	RemoveDefaults bool     `json:"remove-defaults"`
	Trusted        []string `json:"trusted"`
}

// Metadata - Boilerplate for cloud-init hierarchical structure
type Metadata struct {
	CACerts `json:"ca-certs"`
}

// CloudInit - Boilerplate for cloud-init hierarchical structure
type CloudInit struct {
	Metadata `json:"meta-data"`
}

// CloudInitBSS - Boilerplace for cloud-init hierarchical structure
type CloudInitBSS struct {
	Hosts     []string
	CloudInit `json:"cloud-init"`
}

// +kubebuilder:rbac:groups=certificates.hpe.com,resources=trustedcertificates,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=certificates.hpe.com,resources=trustedcertificates/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete

// Reconcile main K8S reconcile method
func (r *TrustedCertificatesReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("trustedcertificates", req.NamespacedName)

	trustedcertificate := &certificateshpecomv1alpha1.TrustedCertificates{}
	err := r.Get(ctx, req.NamespacedName, trustedcertificate)

	if err != nil {
		if k8serrors.IsNotFound(err) {
			log.Info("CR not found (deleted?). Ignoring")
			return ctrl.Result{}, nil // don't reqeueue
		}
	}

	// K8S (Open)API validation should ensure we have at least one source
	// and that the source has a valid type

	// Aggregate all certificates found into source_certs
	sourceCerts := make([]tls.Certificate, 0)

	for _, source := range trustedcertificate.Spec.Sources {

		// per-type validtion of polymorphic config object
		_, err := validateSourceConfig(ctx, source)
		if err != nil {
			log.Info("Unable to validate source config, please check CR and correct: " + err.Error())
			return ctrl.Result{}, nil // don't requeue
		}

		switch sourceType := source.Type; sourceType {
		case "http":
			raw, err := pullSourceHTTP(source)
			if err != nil {
				log.Info("HTTP source pull of: " + source.Config["url"] + " failed. Requeuing")
				return ctrl.Result{}, err //requeue
			}

			if source.Config["format"] == "vault-pki-ca-chain" {
				certs, err := parseFormatVault(raw)
				if err != nil {
					log.Info("Unable to parse vault PKI ca chain response. Requeuing")
					return ctrl.Result{}, err
				}
				sourceCerts = append(sourceCerts, certs)
			}
		default:
			panic("Unknown source type: " + sourceType)
		}
	}

	for _, destination := range trustedcertificate.Spec.Destinations {

		_, err := validateDestinationConfig(ctx, destination)
		if err != nil {
			log.Info("Unable to validate destination config, please check CR and correct: " + err.Error())
			return ctrl.Result{}, nil // don't reqeue
		}

		switch destinationType := destination.Type; destinationType {
		case "configmap":
			err := r.updateDestinationConfigmap(ctx, destination, sourceCerts)
			if err != nil {
				log.Info("Unable to create/update destination configmap. Requeuing")
				return ctrl.Result{}, err
			}
		case "bss":
			err := r.updateDestinationBSS(ctx, destination, sourceCerts)
			if err != nil {
				log.Info("Unable to create/update destination BSS target. Requeuing")
				return ctrl.Result{}, err
			}
		default:
			panic("Unknown destination type: " + destinationType)
		}

	}

	return ctrl.Result{}, nil

}

// SetupWithManager register the operator
func (r *TrustedCertificatesReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certificateshpecomv1alpha1.TrustedCertificates{}).
		Complete(r)
}

// Create or update destination configmap, with provided certificates
func (r *TrustedCertificatesReconciler) updateDestinationConfigmap(ctx context.Context, destination certificateshpecomv1alpha1.Destination, certs []tls.Certificate) error {
	certMap := make(map[string]string)
	certificateBundle := new(bytes.Buffer)

	for _, sourceCertificates := range certs {
		for _, cert := range sourceCertificates.Certificate {
			certPem := new(bytes.Buffer)
			pem.Encode(certPem, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert,
			})
			pemBytes := certPem.Bytes()
			digest := sha256.Sum256(pemBytes)
			certMap[fmt.Sprintf("%x.crt", digest[:8])] = string(pemBytes)
			certificateBundle.Write(pemBytes)
		}
	}
	certMap[destination.Config["bundle_key"]] = string(certificateBundle.Bytes())

	labels := map[string]string{
		"app": destination.Name,
	}

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      destination.Config["name"],
			Namespace: destination.Config["namespace"],
			Labels:    labels,
		},
		Data: certMap,
	}

	foundMap := &corev1.ConfigMap{}
	err := r.Client.Get(ctx, types.NamespacedName{Name: configMap.Name, Namespace: configMap.Namespace}, foundMap)

	// configMap does not exist, try to create it
	if err != nil && k8serrors.IsNotFound(err) {
		err = r.Client.Create(ctx, configMap)
		if err != nil {
			return err
		}
		return nil
	} else if err != nil {
		return err
	}

	// configMap exists, update if needed
	if !reflect.DeepEqual(certMap, foundMap.Data) {
		r.Client.Update(ctx, configMap)
		if err != nil {
			return err
		}
		return nil
	} else if err != nil {
		return err
	}

	return nil
}

// Update cloud-init metadata via BSS, with provided certificates
func (r *TrustedCertificatesReconciler) updateDestinationBSS(ctx context.Context, destination certificateshpecomv1alpha1.Destination, certs []tls.Certificate) error {

	var BSSUpdate CloudInitBSS
	BSSUpdate.Hosts = append(BSSUpdate.Hosts, "Global")
	bssURL := destination.Config["url"]

	if destination.Config["remove_defaults"] == "true" {
		BSSUpdate.CloudInit.Metadata.CACerts.RemoveDefaults = true
	} else {
		BSSUpdate.CloudInit.Metadata.CACerts.RemoveDefaults = false
	}

	for _, sourceCertificates := range certs {
		for _, cert := range sourceCertificates.Certificate {
			certPem := new(bytes.Buffer)
			pem.Encode(certPem, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert,
			})
			BSSUpdate.CloudInit.Metadata.CACerts.Trusted = append(BSSUpdate.CloudInit.Metadata.CACerts.Trusted, string(certPem.Bytes()))
		}
	}

	patch, err := json.Marshal(BSSUpdate)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPatch, bssURL, bytes.NewBuffer(patch))
	if err != nil {
		return err
	}

	req.Header.Set("Context-Type", "application/json")

	HTTPClient := &http.Client{}

	resp, err := HTTPClient.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return nil
	}
	return errors.New("BSS returned a non-200 response")

}

// validateSourceConfig provides for polymorphic source configuration
// validation, by source type.
func validateSourceConfig(ctx context.Context, source certificateshpecomv1alpha1.Source) (certificateshpecomv1alpha1.Source, error) {

	// JSON Schemas for all supported types

	// type http
	var httpSchemaData = []byte(`{
    "$id": "https://certificates.hpe.com/schema/",
    "$comment": "source config schema used to validate HTTP sources",
    "title": "SourceConfigHTTP",
    "type": "object",
    "properties": {
	"url": {
	   "type": "string",
	   "format": "uri"
	 },
	 "encoding": {
	    "type": "string",
	    "pattern": "^(pem)$"
	 },
	 "format": {
	    "type": "string",
	    "pattern": "^(vault-pki-ca-chain)$"
	 }
    },
    "required": ["url","encoding","format"]
  }`)

	rs := &jsonschema.Schema{}

	// Validate schema

	schema := httpSchemaData

	switch sourceType := source.Type; sourceType {
	case "http":
		schema = httpSchemaData
	default:
		panic("Unknown source type: " + sourceType)
	}

	if err := json.Unmarshal(schema, rs); err != nil {
		panic("failed json-schema unmarshal: " + err.Error())
	}

	// Validate config against schema

	config, _ := json.Marshal(&source.Config)
	errs, err := rs.ValidateBytes(ctx, config)
	if err != nil {
		return source, err
	}
	if len(errs) > 0 {
		return source, errs[0] // returns 'first' error encountered
	}

	return source, nil

}

// validateDestinationConfig provides for polymorphic source configuration
// validation, by destination type.
func validateDestinationConfig(ctx context.Context, destination certificateshpecomv1alpha1.Destination) (certificateshpecomv1alpha1.Destination, error) {

	// JSON Schemas for all supported types

	// type configmap
	var configmapSchemaData = []byte(`{
    "$id": "https://certificates.hpe.com/schema/",
    "$comment": "source config schema used to validate configmap destination",
    "title": "DestinationConfigConfigmap",
    "type": "object",
    "properties": {
	"name": {
	   "type": "string"
	 },
	 "namespace": {
	   "type": "string"
	 },
	 "encoding": {
	    "type": "string",
	    "pattern": "^(pem)$"
	 },
	 "bundle_key": {
	   "type": "string"
	 }
    },
    "required": ["name","namespace","encoding", "bundle_key"]
  }`)

	// type bss
	var BSSSchemaData = []byte(`{
		"$id": "https://certificates.hpe.com/schema/",
		"$comment": "source config schema used to validate BSS destination",
		"title": "DestinationConfigBSS",
		"type": "object",
		"properties": {
		"url": {
		   "type": "string"
		 },
		 "encoding": {
			"type": "string",
			"pattern": "^(pem)$"
		 },
		 "remove_defaults": {
			 "type": "string",
			 "pattern": "^(true|false)$"
		 }
		},
		"required": ["url","encoding","remove_defaults"]
	  }`)

	rs := &jsonschema.Schema{}

	// Validate schema

	schema := configmapSchemaData
	switch destinationType := destination.Type; destinationType {
	case "configmap":
		schema = configmapSchemaData
	case "bss":
		schema = BSSSchemaData

	default:
		panic("Unknown destination type: " + destinationType)
	}

	if err := json.Unmarshal(schema, rs); err != nil {
		panic("failed json-schema unmarshal: " + err.Error())
	}

	// Validate config against schema

	config, _ := json.Marshal(&destination.Config)
	errs, err := rs.ValidateBytes(ctx, config)
	if err != nil {
		return destination, err
	}
	if len(errs) > 0 {
		return destination, errs[0] // returns 'first' error encountered
	}

	return destination, nil

}

// pullSourceHTTP attempts to return a byte slice containing the
// response body of an HTTP GET to the url designed in the
// source->item cofig object.
func pullSourceHTTP(source certificateshpecomv1alpha1.Source) ([]byte, error) {

	var nilSlice []byte
	resp, err := http.Get(source.Config["url"])

	if err != nil {
		return nilSlice, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nilSlice, err
	}

	return body, nil
}

// parseFormatVault attempts to parse a Vault PKI
// ca_chain response and return a tls.Certificate object
// that contains one or more certificates.
func parseFormatVault(raw []byte) (tls.Certificate, error) {

	var cert tls.Certificate

	for {
		block, other := pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, block.Bytes)
		} // disregard anything else in PEM that may not be a certificate...
		raw = other
	}

	if len(cert.Certificate) == 0 {
		return cert, fmt.Errorf("unable to parse vault certificates")
	}

	return cert, nil
}
