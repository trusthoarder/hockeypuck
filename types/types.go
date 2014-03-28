package types

import (
	"database/sql/driver"
	"encoding/base64"
	"errors"
	"time"
)


type WrappedTime struct {
    time.Time
}

func (wt WrappedTime) Value() (driver.Value, error) {
    return wt.Time.String(), nil
}

func (wt *WrappedTime) Scan(value interface{}) error {
    switch value.(type) {
    case string:
        var err error
        wt.Time, err = time.Parse("2006-01-02 15:04:05 -0700 MST", value.(string))
        if err != nil {
        	wt.Time, err = time.Parse("2006-01-02T15:04:05-0700", value.(string))
        }
        return err
    case int:
        wt.Time = time.Unix(int64(value.(int)), 0)
        return nil
    default:
        return errors.New("Unsupported type")
    }
}

type WrappedByteArray struct {
    Bytes []byte
}

func (wba WrappedByteArray) Value() (driver.Value, error) {
    return wba.Bytes, nil
}

func (wba *WrappedByteArray) Scan(value interface{}) error {
    var err error
    wba.Bytes, err = base64.StdEncoding.DecodeString(value.(string))
    return err
}
