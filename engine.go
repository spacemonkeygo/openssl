// Copyright (C) 2014 Space Monkey, Inc.
// +build cgo

package openssl

/*
#include "openssl/engine.h"
*/
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"
)

type Engine struct {
	e *C.ENGINE
}

func EngineById(name string) (*Engine, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	e := &Engine{
		e: C.ENGINE_by_id(cname),
	}
	if e.e == nil {
		return nil, fmt.Errorf("engine %s missing", name)
	}
	if C.ENGINE_init(e.e) == 0 {
		C.ENGINE_free(e.e)
		return nil, fmt.Errorf("engine %s not initialized", name)
	}
	runtime.SetFinalizer(e, func(e *Engine) {
		C.ENGINE_finish(e.e)
		C.ENGINE_free(e.e)
	})
	return e, nil
}
