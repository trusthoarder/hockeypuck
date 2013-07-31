/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012, 2013  Casey Marshall

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published by
   the Free Software Foundation, version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package openpgp

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestVerifyUserAttributeSig(t *testing.T) {
	key := MustInputAscKey(t, "uat.asc")
	assert.Equal(t, 1, len(key.userAttributes), "Failed to read user attribute")
	ValidateKey(key)
	assert.Equal(t, 1, len(key.userAttributes), "Failed to validate user attribute")
	uat := key.userAttributes[0]
	imageDats := uat.GetJpegData()
	assert.Equal(t, 1, len(imageDats), "Expected 1 image in uat, found", len(imageDats))
	// TODO: check contents
}

const SKS_DIGEST__SHORTID = "ce353cf4"
const SKS_DIGEST__REFERENCE = "da84f40d830a7be2a3c0b7f2e146bfaa"

func TestSksDigest(t *testing.T) {
	key := MustInputAscKey(t, "sksdigest.asc")
	assert.Equal(t, SKS_DIGEST__SHORTID, key.ShortId())
	assert.Equal(t, SKS_DIGEST__REFERENCE, key.Md5)
}
