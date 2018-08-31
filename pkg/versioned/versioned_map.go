// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package pkg/k8s/client/clientset keeps the version of a particular structure.
package versioned

import (
	"strconv"

	"github.com/cilium/cilium/pkg/lock"
)

type Object struct {
	Data    interface{}
	Version Version
}

type Version int64

func ParseVersion(s string) Version {
	i, _ := strconv.ParseInt(s, 10, 64)
	return Version(i)
}

type UUID string

type Map map[UUID]Object

func (m Map) Add(uuid UUID, obj Object) bool {
	oldObj, ok := m[uuid]
	if !ok || obj.Version > oldObj.Version {
		m[uuid] = obj
		return true
	}
	return false
}

func (m Map) Get(uuid UUID) (Object, bool) {
	o, exists := m[uuid]
	return o, exists
}

func (m Map) Delete(uuid UUID) bool {
	_, exists := m[uuid]
	if exists {
		delete(m, uuid)
	}
	return exists
}

type SyncMap struct {
	m Map
	lock.RWMutex
}

func NewInterfaceMap() *SyncMap {
	return &SyncMap{
		m: Map{},
	}
}

func (sm *SyncMap) Add(uuid UUID, obj Object) bool {
	sm.Lock()
	added := sm.m.Add(uuid, obj)
	sm.Unlock()
	return added
}

func (sm *SyncMap) Delete(uuid UUID) bool {
	sm.Lock()
	exists := sm.m.Delete(uuid)
	sm.Unlock()
	return exists
}

func (sm *SyncMap) Get(uuid UUID) (Object, bool) {
	sm.Lock()
	v, e := sm.m[uuid]
	sm.Unlock()
	return v, e
}

func (sm *SyncMap) DoLocked(f func() error, i func(key UUID, value Object), replace func(old Map) Map) {
	sm.Lock()
	defer sm.Unlock()
	if f() != nil {
		return
	}
	if i != nil {
		for k, v := range sm.m {
			i(k, v)
		}
	}
	if replace != nil {
		sm.m = replace(sm.m)
	}
}
