/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2014  Casey Marshall

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

package errors

import (
	errgo "github.com/juju/errgo/errors"
)

// Lookup key was not found in the database.
var ErrKeyNotFound = errgo.New("Key not found.")

// An internal inconsistency between the stored key material and our indexing was detected.
var ErrInconsistentKey = errgo.New("Stored key is internally inconsistent.")

// Key ID is invalid.
var ErrInvalidKeyId = errgo.New("Invalid key ID.")

// Key hash is invalid.
var ErrInvalidKeyHash = errgo.New("Invalid key hash.")

// A lookup with a short key ID found a collision.
// This is quite possible with short key IDs, remotely possibly with long IDs.
var ErrKeyIdCollision = errgo.New("Key ID matches multiple public keys. Try again with a longer key ID.")

// A query resulted in more responses than we'd care to respond with.
var ErrTooManyResponses = errgo.New("Too many responses.")

// Something was attempted that isn't fully baked yet.
var ErrUnsupportedOperation = errgo.New("Unsupported operation.")

// Template path was not found. Installation or configuration problem.
var ErrTemplatePathNotFound = errgo.New("Could not find templates. Check your installation and configuration.")
