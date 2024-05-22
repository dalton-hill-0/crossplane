/*
Copyright 2020 The Crossplane Authors.

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

// Package xcrd generates CustomResourceDefinitions from Crossplane definitions.
//
// v1.JSONSchemaProps is incompatible with controller-tools (as of 0.2.4)
// because it is missing JSON tags and uses float64, which is a disallowed type.
// We thus copy the entire struct as CRDSpecTemplate. See the below issue:
// https://github.com/kubernetes-sigs/controller-tools/issues/291
package xcrd

import (
	"encoding/json"
	"fmt"

	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	appcfgextv1 "k8s.io/apiextensions-apiserver/pkg/client/applyconfiguration/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	appcfgmetav1 "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/crossplane/crossplane-runtime/pkg/errors"
	"github.com/crossplane/crossplane-runtime/pkg/meta"

	v1 "github.com/crossplane/crossplane/apis/apiextensions/v1"
)

// Category names for generated claim and composite CRDs.
const (
	CategoryClaim     = "claim"
	CategoryComposite = "composite"
)

const (
	errFmtGenCrd                   = "cannot generate CRD for %q %q"
	errFmtModCrd                   = "cannot modify CRD for %q %q"
	errParseValidation             = "cannot parse validation schema"
	errInvalidClaimNames           = "invalid resource claim names"
	errMissingClaimNames           = "missing names"
	errFmtConflictingClaimName     = "%q conflicts with composite resource name"
	errCustomResourceValidationNil = "custom resource validation cannot be nil"
	errConvertPrinterColumns       = "cannot convert printer columns"
)

// ForCompositeResource derives the CustomResourceDefinition for a composite
// resource from the supplied CompositeResourceDefinition.
func ForCompositeResource(xrd *v1.CompositeResourceDefinition) (*extv1.CustomResourceDefinition, error) {
	crd := &extv1.CustomResourceDefinition{
		Spec: extv1.CustomResourceDefinitionSpec{
			Scope:      extv1.ClusterScoped,
			Group:      xrd.Spec.Group,
			Names:      xrd.Spec.Names,
			Versions:   make([]extv1.CustomResourceDefinitionVersion, len(xrd.Spec.Versions)),
			Conversion: xrd.Spec.Conversion,
		},
	}

	crd.SetName(xrd.GetName())
	setCrdMetadata(crd, xrd)
	crd.SetOwnerReferences([]metav1.OwnerReference{meta.AsController(
		meta.TypedReferenceTo(xrd, v1.CompositeResourceDefinitionGroupVersionKind),
	)})

	crd.Spec.Names.Categories = append(crd.Spec.Names.Categories, CategoryComposite)

	// The composite name is used as a label value, so we must ensure it is not
	// longer.
	const maxCompositeNameLength = 63

	for i, vr := range xrd.Spec.Versions {
		crdv, err := genCrdVersion(vr, maxCompositeNameLength)
		if err != nil {
			return nil, errors.Wrapf(err, errFmtGenCrd, "Composite Resource", xrd.Name)
		}
		crdv.AdditionalPrinterColumns = append(crdv.AdditionalPrinterColumns, CompositeResourcePrinterColumns()...)
		props := CompositeResourceSpecProps()
		if xrd.Spec.DefaultCompositionUpdatePolicy != nil {
			cup := props["compositionUpdatePolicy"]
			cup.Default = &extv1.JSON{Raw: []byte(fmt.Sprintf("\"%s\"", *xrd.Spec.DefaultCompositionUpdatePolicy))}
			props["compositionUpdatePolicy"] = cup
		}
		for k, v := range props {
			crdv.Schema.OpenAPIV3Schema.Properties["spec"].Properties[k] = v
		}
		crd.Spec.Versions[i] = *crdv
	}

	return crd, nil
}

func ModifyApplyConfigurationForCompositeResource(crd *appcfgextv1.CustomResourceDefinitionApplyConfiguration, xrd *v1.CompositeResourceDefinition) error { //nolint:gocognit
	if crd.Name == nil {
		crd.WithName(xrd.GetName())
	}

	if crd.Spec == nil {
		crd.WithSpec(appcfgextv1.CustomResourceDefinitionSpec())
	}
	crd.Spec.WithScope(extv1.ClusterScoped)
	crd.Spec.WithGroup(xrd.Spec.Group)

	if crd.Spec.Names == nil {
		crd.Spec.WithNames(appcfgextv1.CustomResourceDefinitionNames())
	}
	crd.Spec.Names.WithPlural(xrd.Spec.Names.Plural)
	crd.Spec.Names.WithSingular(xrd.Spec.Names.Singular)
	crd.Spec.Names.WithShortNames(xrd.Spec.Names.ShortNames...)
	crd.Spec.Names.WithKind(xrd.Spec.Names.Kind)
	crd.Spec.Names.WithListKind(xrd.Spec.Names.ListKind)
	crd.Spec.Names.WithCategories(xrd.Spec.Names.Categories...)
	crd.Spec.Names.Categories = append(crd.Spec.Names.Categories, CategoryComposite)

	if xrd.Spec.Conversion != nil {
		if crd.Spec.Conversion == nil {
			crd.Spec.WithConversion(appcfgextv1.CustomResourceConversion())
		}
		xConversion := xrd.Spec.Conversion
		cConversion := crd.Spec.Conversion

		if xConversion.Strategy != "" {
			cConversion.WithStrategy(xrd.Spec.Conversion.Strategy)
		}

		if xConversion.Webhook != nil {
			if cConversion.Webhook == nil {
				crd.Spec.Conversion.WithWebhook(appcfgextv1.WebhookConversion())
			}
			xWebhook := xrd.Spec.Conversion.Webhook
			cWebhook := crd.Spec.Conversion.Webhook

			cWebhook.ConversionReviewVersions = xWebhook.ConversionReviewVersions

			if xWebhook.ClientConfig != nil {
				if cWebhook.ClientConfig == nil {
					cWebhook.WithClientConfig(appcfgextv1.WebhookClientConfig())
				}
				xClientConfig := xWebhook.ClientConfig
				cClientConfig := cWebhook.ClientConfig

				cClientConfig.URL = xClientConfig.URL
				cClientConfig.CABundle = xClientConfig.CABundle

				if xClientConfig.Service != nil {
					if cClientConfig.Service == nil {
						cClientConfig.WithService(appcfgextv1.ServiceReference())
					}
					xService := xClientConfig.Service
					cService := cClientConfig.Service

					if xService.Name != "" {
						cService.WithName(xService.Name)
					}
					if xService.Namespace != "" {
						cService.WithNamespace(xService.Namespace)
					}
					cService.Path = xService.Path
					cService.Port = xService.Port
				}
			}
		}
	}

	setCrdMetadataApplyConfiguration(crd, xrd)

	ownerKind, ownerVersion := v1.CompositeResourceDefinitionGroupVersionKind.ToAPIVersionAndKind()
	ownerRef := appcfgmetav1.OwnerReference().
		WithName(xrd.Name).
		WithUID(xrd.GetUID()).
		WithAPIVersion(ownerVersion).
		WithKind(ownerKind).
		WithBlockOwnerDeletion(true).
		WithController(true)
	crd.WithOwnerReferences(ownerRef)

	for i, xrdv := range xrd.Spec.Versions {
		// TODO(dalton): note requirement on index sharing, doubt this would be
		// broken by anyone, but in theory someone could mess this up	since we are
		// loading data on CRD version index and patching that into what we create
		// from the XRD
		if i >= len(crd.Spec.Versions) {
			crd.Spec.Versions = append(crd.Spec.Versions, appcfgextv1.CustomResourceDefinitionVersionApplyConfiguration{})
		}
		crdv := &crd.Spec.Versions[i]
		if err := modifyCrdVersionApplyConfig(crdv, xrdv); err != nil {
			return errors.Wrapf(err, errFmtModCrd, "Composite Resource", xrd.Name)
		}
		crdv.AdditionalPrinterColumns = append(crdv.AdditionalPrinterColumns, CompositeResourcePrinterColumnsAppCfg()...)
		props := CompositeResourceSpecPropsAppCfg()
		if xrd.Spec.DefaultCompositionUpdatePolicy != nil {
			cup := props["compositionUpdatePolicy"]
			cup.Default = &extv1.JSON{Raw: []byte(fmt.Sprintf("\"%s\"", *xrd.Spec.DefaultCompositionUpdatePolicy))}
			props["compositionUpdatePolicy"] = cup
		}
		for k, v := range props {
			crdv.Schema.OpenAPIV3Schema.Properties["spec"].Properties[k] = v
		}
	}

	return nil
}

// ForCompositeResourceClaim derives the CustomResourceDefinition for a
// composite resource claim from the supplied CompositeResourceDefinition.
func ForCompositeResourceClaim(xrd *v1.CompositeResourceDefinition) (*extv1.CustomResourceDefinition, error) {
	if err := validateClaimNames(xrd); err != nil {
		return nil, errors.Wrap(err, errInvalidClaimNames)
	}

	crd := &extv1.CustomResourceDefinition{
		Spec: extv1.CustomResourceDefinitionSpec{
			Scope:      extv1.NamespaceScoped,
			Group:      xrd.Spec.Group,
			Names:      *xrd.Spec.ClaimNames,
			Versions:   make([]extv1.CustomResourceDefinitionVersion, len(xrd.Spec.Versions)),
			Conversion: xrd.Spec.Conversion,
		},
	}

	crd.SetName(xrd.Spec.ClaimNames.Plural + "." + xrd.Spec.Group)
	setCrdMetadata(crd, xrd)
	crd.SetOwnerReferences([]metav1.OwnerReference{meta.AsController(
		meta.TypedReferenceTo(xrd, v1.CompositeResourceDefinitionGroupVersionKind),
	)})

	crd.Spec.Names.Categories = append(crd.Spec.Names.Categories, CategoryClaim)

	// 63 because the names are used as label values. We don't put 63-6
	// (generateName suffix length) here because the name generator shortens
	// the base to 57 automatically before appending the suffix.
	const maxClaimNameLength = 63

	for i, vr := range xrd.Spec.Versions {
		crdv, err := genCrdVersion(vr, maxClaimNameLength)
		if err != nil {
			return nil, errors.Wrapf(err, errFmtGenCrd, "Composite Resource Claim", xrd.Name)
		}
		crdv.AdditionalPrinterColumns = append(crdv.AdditionalPrinterColumns, CompositeResourceClaimPrinterColumns()...)
		props := CompositeResourceClaimSpecProps()
		if xrd.Spec.DefaultCompositeDeletePolicy != nil {
			cdp := props["compositeDeletePolicy"]
			cdp.Default = &extv1.JSON{Raw: []byte(fmt.Sprintf("\"%s\"", *xrd.Spec.DefaultCompositeDeletePolicy))}
			props["compositeDeletePolicy"] = cdp
		}
		for k, v := range props {
			crdv.Schema.OpenAPIV3Schema.Properties["spec"].Properties[k] = v
		}
		crd.Spec.Versions[i] = *crdv
	}

	return crd, nil
}

func modifyCrdVersionApplyConfig(crdv *appcfgextv1.CustomResourceDefinitionVersionApplyConfiguration, xrdv v1.CompositeResourceDefinitionVersion) error {
	crdv.WithName(xrdv.Name)
	crdv.WithServed(xrdv.Served)
	crdv.WithStorage(xrdv.Served)
	crdv.WithDeprecated(ptr.Deref(xrdv.Deprecated, false))
	crdv.DeprecationWarning = xrdv.DeprecationWarning

	for _, c := range xrdv.AdditionalPrinterColumns {
		bs, err := c.Marshal()
		if err != nil {
			return errors.Wrap(err, errConvertPrinterColumns)
		}

		appCfg := appcfgextv1.CustomResourceColumnDefinition()
		if err := json.Unmarshal(bs, appCfg); err != nil {
			return errors.Wrap(err, errConvertPrinterColumns)
		}
		crdv.AdditionalPrinterColumns = append(crdv.AdditionalPrinterColumns, *appCfg)
	}

	// TODO: additionalprintercolumns

	if crdv.Schema == nil {
		crdv.WithSchema(appcfgextv1.CustomResourceValidation())
	}
	if crdv.Schema.OpenAPIV3Schema == nil {
		crdv.Schema.WithOpenAPIV3Schema(appcfgextv1.JSONSchemaProps())
	}
	BasePropsApplyConfig(crdv.Schema.OpenAPIV3Schema)

	if crdv.Subresources == nil {
		crdv.WithSubresources(appcfgextv1.CustomResourceSubresources())
	}
	crdv.Subresources.WithStatus(extv1.CustomResourceSubresourceStatus{})

	s, err := parseSchemaAppCfg(xrdv.Schema)
	if err != nil {
		return errors.Wrapf(err, errParseValidation)
	}

	if s == nil {
		return errors.New(errCustomResourceValidationNil)
	}

	crdv.Schema.OpenAPIV3Schema.Description = s.Description

	maxLength := int64(63)
	if old := s.Properties["metadata"].Properties["name"].MaxLength; old != nil && *old < maxLength {
		maxLength = *old
	}

	xName := crdv.Schema.OpenAPIV3Schema.Properties["name"]
	xName.WithMaxLength(maxLength)
	xName.WithType("string")
	xMeta := crdv.Schema.OpenAPIV3Schema.Properties["metadata"]
	if xMeta.Properties == nil {
		xMeta.Properties = make(map[string]appcfgextv1.JSONSchemaPropsApplyConfiguration)
	}
	xMeta.Properties["name"] = xName
	crdv.Schema.OpenAPIV3Schema.Properties["metadata"] = xMeta

	xSpec := s.Properties["spec"]
	cSpec := crdv.Schema.OpenAPIV3Schema.Properties["spec"]
	// TODO(dalton): there is some logic which prevents this from having
	// duplicates?
	cSpec.Required = append(cSpec.Required, xSpec.Required...)
	if cSpec.XValidations == nil {
		cSpec.XValidations = &extv1.ValidationRules{}
	}
	if xSpec.XValidations == nil {
		xSpec.XValidations = &extv1.ValidationRules{}
	}
	cSpec.WithXValidations(append(*cSpec.XValidations, *xSpec.XValidations...))
	cSpec.OneOf = append(cSpec.OneOf, xSpec.OneOf...)
	cSpec.Description = xSpec.Description
	if cSpec.Properties == nil {
		cSpec.Properties = make(map[string]appcfgextv1.JSONSchemaPropsApplyConfiguration)
	}
	for k, v := range xSpec.Properties {
		cSpec.Properties[k] = v
	}
	crdv.Schema.OpenAPIV3Schema.Properties["spec"] = cSpec

	xStatus := s.Properties["status"]
	cStatus := crdv.Schema.OpenAPIV3Schema.Properties["status"]
	cStatus.Required = xStatus.Required
	cStatus.XValidations = xStatus.XValidations
	cStatus.Description = xStatus.Description
	cStatus.OneOf = xStatus.OneOf
	for k, v := range xStatus.Properties {
		cStatus.Properties[k] = v
	}
	for k, v := range CompositeResourceStatusPropsAppCfg() {
		cStatus.Properties[k] = v
	}
	crdv.Schema.OpenAPIV3Schema.Properties["status"] = cStatus

	return nil
}

func genCrdVersion(vr v1.CompositeResourceDefinitionVersion, maxNameLength int64) (*extv1.CustomResourceDefinitionVersion, error) {
	crdv := extv1.CustomResourceDefinitionVersion{
		Name:                     vr.Name,
		Served:                   vr.Served,
		Storage:                  vr.Referenceable,
		Deprecated:               ptr.Deref(vr.Deprecated, false),
		DeprecationWarning:       vr.DeprecationWarning,
		AdditionalPrinterColumns: vr.AdditionalPrinterColumns,
		Schema: &extv1.CustomResourceValidation{
			OpenAPIV3Schema: BaseProps(),
		},
		Subresources: &extv1.CustomResourceSubresources{
			Status: &extv1.CustomResourceSubresourceStatus{},
		},
	}
	s, err := parseSchema(vr.Schema)
	if err != nil {
		return nil, errors.Wrapf(err, errParseValidation)
	}

	if s == nil {
		return nil, errors.New(errCustomResourceValidationNil)
	}

	crdv.Schema.OpenAPIV3Schema.Description = s.Description

	maxLength := maxNameLength
	if old := s.Properties["metadata"].Properties["name"].MaxLength; old != nil && *old < maxLength {
		maxLength = *old
	}
	xName := crdv.Schema.OpenAPIV3Schema.Properties["metadata"].Properties["name"]
	xName.MaxLength = ptr.To(maxLength)
	xName.Type = "string"
	xMetaData := crdv.Schema.OpenAPIV3Schema.Properties["metadata"]
	xMetaData.Properties = map[string]extv1.JSONSchemaProps{"name": xName}
	crdv.Schema.OpenAPIV3Schema.Properties["metadata"] = xMetaData

	xSpec := s.Properties["spec"]
	cSpec := crdv.Schema.OpenAPIV3Schema.Properties["spec"]
	cSpec.Required = append(cSpec.Required, xSpec.Required...)
	cSpec.XValidations = append(cSpec.XValidations, xSpec.XValidations...)
	cSpec.OneOf = append(cSpec.OneOf, xSpec.OneOf...)
	cSpec.Description = xSpec.Description
	for k, v := range xSpec.Properties {
		cSpec.Properties[k] = v
	}
	crdv.Schema.OpenAPIV3Schema.Properties["spec"] = cSpec

	xStatus := s.Properties["status"]
	cStatus := crdv.Schema.OpenAPIV3Schema.Properties["status"]
	cStatus.Required = xStatus.Required
	cStatus.XValidations = xStatus.XValidations
	cStatus.Description = xStatus.Description
	cStatus.OneOf = xStatus.OneOf
	for k, v := range xStatus.Properties {
		cStatus.Properties[k] = v
	}
	for k, v := range CompositeResourceStatusProps() {
		cStatus.Properties[k] = v
	}
	crdv.Schema.OpenAPIV3Schema.Properties["status"] = cStatus
	return &crdv, nil
}

func validateClaimNames(d *v1.CompositeResourceDefinition) error {
	if d.Spec.ClaimNames == nil {
		return errors.New(errMissingClaimNames)
	}

	if n := d.Spec.ClaimNames.Kind; n == d.Spec.Names.Kind {
		return errors.Errorf(errFmtConflictingClaimName, n)
	}

	if n := d.Spec.ClaimNames.Plural; n == d.Spec.Names.Plural {
		return errors.Errorf(errFmtConflictingClaimName, n)
	}

	if n := d.Spec.ClaimNames.Singular; n != "" && n == d.Spec.Names.Singular {
		return errors.Errorf(errFmtConflictingClaimName, n)
	}

	if n := d.Spec.ClaimNames.ListKind; n != "" && n == d.Spec.Names.ListKind {
		return errors.Errorf(errFmtConflictingClaimName, n)
	}

	return nil
}

func parseSchema(v *v1.CompositeResourceValidation) (*extv1.JSONSchemaProps, error) {
	if v == nil {
		return nil, nil
	}

	s := &extv1.JSONSchemaProps{}
	if err := json.Unmarshal(v.OpenAPIV3Schema.Raw, s); err != nil {
		return nil, errors.Wrap(err, errParseValidation)
	}
	return s, nil
}

// TODO(dalton): double-check this works as expected.
func parseSchemaAppCfg(v *v1.CompositeResourceValidation) (*appcfgextv1.JSONSchemaPropsApplyConfiguration, error) {
	if v == nil {
		return nil, nil
	}

	s := appcfgextv1.JSONSchemaProps()
	if err := json.Unmarshal(v.OpenAPIV3Schema.Raw, s); err != nil {
		return nil, errors.Wrap(err, errParseValidation)
	}
	return s, nil
}

// setCrdMetadata sets the labels and annotations on the CRD.
func setCrdMetadata(crd *extv1.CustomResourceDefinition, xrd *v1.CompositeResourceDefinition) *extv1.CustomResourceDefinition {
	crd.SetLabels(xrd.GetLabels())
	if xrd.Spec.Metadata != nil {
		if xrd.Spec.Metadata.Labels != nil {
			inheritedLabels := crd.GetLabels()
			if inheritedLabels == nil {
				inheritedLabels = map[string]string{}
			}
			for k, v := range xrd.Spec.Metadata.Labels {
				inheritedLabels[k] = v
			}
			crd.SetLabels(inheritedLabels)
		}
		if xrd.Spec.Metadata.Annotations != nil {
			crd.SetAnnotations(xrd.Spec.Metadata.Annotations)
		}
	}
	return crd
}

func setCrdMetadataApplyConfiguration(crd *appcfgextv1.CustomResourceDefinitionApplyConfiguration, xrd *v1.CompositeResourceDefinition) {
	// Set labels.
	labelsFromXRD := make(map[string]string)
	for k, v := range xrd.GetLabels() {
		labelsFromXRD[k] = v
	}
	if xrd.Spec.Metadata != nil {
		for k, v := range xrd.Spec.Metadata.Labels {
			labelsFromXRD[k] = v
		}
	}
	if len(labelsFromXRD) > 0 {
		if crd.Labels == nil {
			crd.Labels = make(map[string]string)
		}
		for k, v := range labelsFromXRD {
			crd.Labels[k] = v
		}
	}

	// Set annotations.
	if xrd.Spec.Metadata != nil && len(xrd.Spec.Metadata.Annotations) > 0 {
		if crd.Annotations == nil {
			crd.Annotations = make(map[string]string)
		}
		for k, v := range xrd.Spec.Metadata.Annotations {
			crd.Annotations[k] = v
		}
	}
}

// IsEstablished is a helper function to check whether api-server is ready
// to accept the instances of registered CRD.
func IsEstablished(s extv1.CustomResourceDefinitionStatus) bool {
	for _, c := range s.Conditions {
		if c.Type == extv1.Established {
			return c.Status == extv1.ConditionTrue
		}
	}
	return false
}
