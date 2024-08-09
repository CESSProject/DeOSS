/*
	Copyright (C) CESS. All rights reserved.
	Copyright (C) Cumulus Encrypted Storage System. All rights reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package coordinate

import (
	"fmt"
	"math"
	"strconv"
)

type Coordinate struct {
	Longitude float64 `json:"longitude"` // -180 ~ 0 ~ 180
	Latitude  float64 `json:"latitude"`  // -90 ~ 0 ~ 90
}

type Range struct {
	Coordinate []Coordinate `json:"coordinate"`
}

func ConvertToRange(longitude, latitude []string) (Range, error) {
	longitudelength := len(longitude)
	latitudelength := len(latitude)
	if longitudelength != latitudelength {
		return Range{}, fmt.Errorf("longitude length(%d) not equal latitude length(%d)", longitudelength, latitudelength)
	}
	if longitudelength == 0 {
		return Range{}, nil
	}
	if longitudelength < 3 {
		return Range{}, fmt.Errorf("the number of coordinate points (%d) is less than 3", longitudelength)
	}
	var coordinates Range
	coordinates.Coordinate = make([]Coordinate, longitudelength)
	for i := 0; i < longitudelength; i++ {
		longitudef, err := strconv.ParseFloat(longitude[i], 64)
		if err != nil {
			return Range{}, fmt.Errorf("invalid longitude point: %s", longitude[i])
		}
		latitudef, err := strconv.ParseFloat(latitude[i], 64)
		if err != nil {
			return Range{}, fmt.Errorf("invalid latitude point: %s", latitude[i])
		}
		coordinates.Coordinate[i] = Coordinate{Longitude: longitudef, Latitude: latitudef}
	}
	return coordinates, nil
}

func PointInRange(point Coordinate, area Range) bool {
	pointNum := len(area.Coordinate)
	intersectCount := 0
	precision := 2e-10
	p1 := Coordinate{}
	p2 := Coordinate{}
	p := point

	p1 = area.Coordinate[0]
	for i := 0; i < pointNum; i++ {
		if p.Longitude == p1.Longitude && p.Latitude == p1.Latitude {
			return true
		}
		p2 = area.Coordinate[i%pointNum]
		if p.Latitude < math.Min(p1.Latitude, p2.Latitude) || p.Latitude > math.Max(p1.Latitude, p2.Latitude) {
			p1 = p2
			continue
		}

		if p.Latitude > math.Min(p1.Latitude, p2.Latitude) && p.Latitude < math.Max(p1.Latitude, p2.Latitude) {
			if p.Longitude <= math.Max(p1.Longitude, p2.Longitude) {
				if p1.Latitude == p2.Latitude && p.Longitude >= math.Min(p1.Longitude, p2.Longitude) {
					return true
				}

				if p1.Longitude == p2.Longitude {
					if p1.Longitude == p.Longitude {
						return true
					} else {
						intersectCount++
					}
				} else {
					xinters := (p.Latitude-p1.Latitude)*(p2.Longitude-p1.Longitude)/(p2.Latitude-p1.Latitude) + p1.Longitude
					if math.Abs(p.Longitude-xinters) < precision {
						return true
					}

					if p.Longitude < xinters {
						intersectCount++
					}
				}
			}
		} else {
			if p.Latitude == p2.Latitude && p.Longitude <= p2.Longitude {
				p3 := area.Coordinate[(i+1)%pointNum]
				if p.Latitude >= math.Min(p1.Latitude, p3.Latitude) && p.Latitude <= math.Max(p1.Latitude, p3.Latitude) {
					intersectCount++
				} else {
					intersectCount += 2
				}
			}
		}
		p1 = p2
	}
	if intersectCount%2 == 0 {
		return false
	} else {
		return true
	}
}
