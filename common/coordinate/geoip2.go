/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package coordinate

import (
	_ "embed"
	"net"

	"github.com/oschwald/geoip2-golang"
)

var geoip *geoip2.Reader

//go:embed GeoLite2-City.mmdb
var geoLite2 string

func init() {
	var err error
	geoip, err = geoip2.FromBytes([]byte(geoLite2))
	if err != nil {
		panic(err)
	}
}

func GetCity(ip net.IP) (*geoip2.City, error) {
	return geoip.City(ip)
}

func GetCountry(ip net.IP) (*geoip2.Country, error) {
	return geoip.Country(ip)
}
