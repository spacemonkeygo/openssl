// Copyright (C) 2014 Space Monkey, Inc.

package utils

import (
    "errors"
    "strings"
)

// ErrorGroup collates errors
type ErrorGroup struct {
    Errors []error
}

// Add adds an error to an existing error group
func (e *ErrorGroup) Add(err error) {
    if err != nil {
        e.Errors = append(e.Errors, err)
    }
}

// Finalize returns an error corresponding to the ErrorGroup state. If there's
// no errors in the group, finalize returns nil. If there's only one error,
// Finalize returns that error. Otherwise, Finalize will make a new error
// consisting of the messages from the constituent errors.
func (e *ErrorGroup) Finalize() error {
    if len(e.Errors) == 0 {
        return nil
    }
    if len(e.Errors) == 1 {
        return e.Errors[0]
    }
    msgs := make([]string, 0, len(e.Errors))
    for _, err := range e.Errors {
        msgs = append(msgs, err.Error())
    }
    return errors.New(strings.Join(msgs, "\n"))
}
