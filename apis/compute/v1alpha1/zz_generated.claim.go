/*
Copyright 2019 The Crossplane Authors.

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

// Code generated by angryjet. DO NOT EDIT.

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	runtimev1alpha1 "github.com/crossplaneio/crossplane-runtime/apis/core/v1alpha1"
)

// GetBindingPhase of this KubernetesCluster.
func (cm *KubernetesCluster) GetBindingPhase() runtimev1alpha1.BindingPhase {
	return cm.Status.GetBindingPhase()
}

// GetClassReference of this KubernetesCluster.
func (cm *KubernetesCluster) GetClassReference() *corev1.ObjectReference {
	return cm.Spec.ClassReference
}

// GetClassSelector of this KubernetesCluster.
func (cm *KubernetesCluster) GetClassSelector() *metav1.LabelSelector {
	return cm.Spec.ClassSelector
}

// GetCondition of this KubernetesCluster.
func (cm *KubernetesCluster) GetCondition(ct runtimev1alpha1.ConditionType) runtimev1alpha1.Condition {
	return cm.Status.GetCondition(ct)
}

// GetResourceReference of this KubernetesCluster.
func (cm *KubernetesCluster) GetResourceReference() *corev1.ObjectReference {
	return cm.Spec.ResourceReference
}

// GetWriteConnectionSecretToReference of this KubernetesCluster.
func (cm *KubernetesCluster) GetWriteConnectionSecretToReference() *runtimev1alpha1.LocalSecretReference {
	return cm.Spec.WriteConnectionSecretToReference
}

// SetBindingPhase of this KubernetesCluster.
func (cm *KubernetesCluster) SetBindingPhase(p runtimev1alpha1.BindingPhase) {
	cm.Status.SetBindingPhase(p)
}

// SetClassReference of this KubernetesCluster.
func (cm *KubernetesCluster) SetClassReference(r *corev1.ObjectReference) {
	cm.Spec.ClassReference = r
}

// SetClassSelector of this KubernetesCluster.
func (cm *KubernetesCluster) SetClassSelector(s *metav1.LabelSelector) {
	cm.Spec.ClassSelector = s
}

// SetConditions of this KubernetesCluster.
func (cm *KubernetesCluster) SetConditions(c ...runtimev1alpha1.Condition) {
	cm.Status.SetConditions(c...)
}

// SetResourceReference of this KubernetesCluster.
func (cm *KubernetesCluster) SetResourceReference(r *corev1.ObjectReference) {
	cm.Spec.ResourceReference = r
}

// SetWriteConnectionSecretToReference of this KubernetesCluster.
func (cm *KubernetesCluster) SetWriteConnectionSecretToReference(r *runtimev1alpha1.LocalSecretReference) {
	cm.Spec.WriteConnectionSecretToReference = r
}

// GetBindingPhase of this MachineInstance.
func (cm *MachineInstance) GetBindingPhase() runtimev1alpha1.BindingPhase {
	return cm.Status.GetBindingPhase()
}

// GetClassReference of this MachineInstance.
func (cm *MachineInstance) GetClassReference() *corev1.ObjectReference {
	return cm.Spec.ClassReference
}

// GetClassSelector of this MachineInstance.
func (cm *MachineInstance) GetClassSelector() *metav1.LabelSelector {
	return cm.Spec.ClassSelector
}

// GetCondition of this MachineInstance.
func (cm *MachineInstance) GetCondition(ct runtimev1alpha1.ConditionType) runtimev1alpha1.Condition {
	return cm.Status.GetCondition(ct)
}

// GetResourceReference of this MachineInstance.
func (cm *MachineInstance) GetResourceReference() *corev1.ObjectReference {
	return cm.Spec.ResourceReference
}

// GetWriteConnectionSecretToReference of this MachineInstance.
func (cm *MachineInstance) GetWriteConnectionSecretToReference() *runtimev1alpha1.LocalSecretReference {
	return cm.Spec.WriteConnectionSecretToReference
}

// SetBindingPhase of this MachineInstance.
func (cm *MachineInstance) SetBindingPhase(p runtimev1alpha1.BindingPhase) {
	cm.Status.SetBindingPhase(p)
}

// SetClassReference of this MachineInstance.
func (cm *MachineInstance) SetClassReference(r *corev1.ObjectReference) {
	cm.Spec.ClassReference = r
}

// SetClassSelector of this MachineInstance.
func (cm *MachineInstance) SetClassSelector(s *metav1.LabelSelector) {
	cm.Spec.ClassSelector = s
}

// SetConditions of this MachineInstance.
func (cm *MachineInstance) SetConditions(c ...runtimev1alpha1.Condition) {
	cm.Status.SetConditions(c...)
}

// SetResourceReference of this MachineInstance.
func (cm *MachineInstance) SetResourceReference(r *corev1.ObjectReference) {
	cm.Spec.ResourceReference = r
}

// SetWriteConnectionSecretToReference of this MachineInstance.
func (cm *MachineInstance) SetWriteConnectionSecretToReference(r *runtimev1alpha1.LocalSecretReference) {
	cm.Spec.WriteConnectionSecretToReference = r
}
