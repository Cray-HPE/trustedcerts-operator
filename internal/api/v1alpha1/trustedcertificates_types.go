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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// SourceDest Common certificate source and destination struct
type SourceDest struct {
	// +kubebuilder:validation:MaxLength=255
	// +kubebuilder:validation:MinLength=1
	Name   string            `json:"name"`
	Config map[string]string `json:"config"`
}

// Source Certificate source struct
type Source struct {
	// +kubebuilder:validation:Pattern="(http)"
	Type       string `json:"type"`
	SourceDest `json:",inline"`
}

// Destination Certificate destination struct
type Destination struct {
	// +kubebuilder:validation:Pattern="(configmap|bss)"
	Type       string `json:"type"`
	SourceDest `json:",inline"`
}

// TrustedCertificatesSpec defines the desired state of TrustedCertificates
type TrustedCertificatesSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// +kubebuilder:validation:MinItems=1
	Sources []Source `json:"sources"`
	// +kubebuilder:validation:MinItems=1
	Destinations []Destination `json:"destinations"`
}

// TrustedCertificatesStatus defines the observed state of TrustedCertificates
type TrustedCertificatesStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// TrustedCertificates is the Schema for the trustedcertificates API
type TrustedCertificates struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TrustedCertificatesSpec   `json:"spec,omitempty"`
	Status TrustedCertificatesStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TrustedCertificatesList contains a list of TrustedCertificates
type TrustedCertificatesList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TrustedCertificates `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TrustedCertificates{}, &TrustedCertificatesList{})
}
