package ntp

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/pkg/errors"
)

const (
	// ntpPacketSize is the size of an NTPv4 packet without extensions.
	ntpPacketSize = 48
	// ntpVersion is the protocol version used for requests.
	ntpVersion = 4
	// ntpModeClient is the client association mode.
	ntpModeClient = 3
	// ntpEpochOffset is the seconds between the NTP (1900) and Unix (1970) epochs.
	ntpEpochOffset = 2208988800
)

// Response is a parsed NTP server response.
type Response struct {
	Version        int       `json:"version"`
	Mode           int       `json:"mode"`
	Stratum        int       `json:"stratum"`
	Poll           int       `json:"poll"`
	Precision      int       `json:"precision"`
	RootDelay      float64   `json:"root_delay"`
	RootDispersion float64   `json:"root_dispersion"`
	ReferenceID    string    `json:"ref_id"`
	ReferenceTime  time.Time `json:"ref_time"`
	OriginTime     time.Time `json:"origin_time"`
	ReceiveTime    time.Time `json:"receive_time"`
	TransmitTime   time.Time `json:"transmit_time"`
	Delay          float64   `json:"delay"`
	Offset         float64   `json:"offset"`
}

// marshalRequest encodes a client request packet carrying the given transmit
// timestamp.
func marshalRequest(transmit time.Time) []byte {
	packet := make([]byte, ntpPacketSize)
	packet[0] = byte(0<<6 | ntpVersion<<3 | ntpModeClient)
	putNTPTime(packet[40:44], packet[44:48], transmit)
	return packet
}

// parseResponse decodes a server response packet. receiveTime is the local
// time at which the packet was received and is used for delay/offset math.
func parseResponse(packet []byte, receiveTime time.Time) (*Response, error) {
	if len(packet) < ntpPacketSize {
		return nil, errors.Errorf("invalid ntp response size: %d", len(packet))
	}
	if packet[0]&0x7 != 4 && packet[0]&0x7 != 5 {
		return nil, errors.Errorf("invalid ntp response mode: %d", packet[0]&0x7)
	}

	stratum := int(packet[1])
	originTime := ntpTimeToTime(packet[24:32])
	recvTime := ntpTimeToTime(packet[32:40])
	transmitTime := ntpTimeToTime(packet[40:48])

	response := &Response{
		Version:        int(packet[0]>>3) & 0x7,
		Mode:           int(packet[0]) & 0x7,
		Stratum:        stratum,
		Poll:           int(packet[2]),
		Precision:      int(int8(packet[3])),
		RootDelay:      fixedPoint16(packet[4:8]),
		RootDispersion: fixedPoint16(packet[8:12]),
		ReferenceID:    referenceIDString(stratum, packet[12:16]),
		ReferenceTime:  ntpTimeToTime(packet[16:24]),
		OriginTime:     originTime,
		ReceiveTime:    recvTime,
		TransmitTime:   transmitTime,
	}
	// RFC 5905: delay = (T4 - T1) - (T3 - T2), offset = ((T2 - T1) + (T3 - T4)) / 2
	response.Delay = receiveTime.Sub(originTime).Seconds() - transmitTime.Sub(recvTime).Seconds()
	response.Offset = (recvTime.Sub(originTime).Seconds() + transmitTime.Sub(receiveTime).Seconds()) / 2
	return response, nil
}

// referenceIDString renders the reference identifier. Stratum 0 and 1 servers
// carry an ASCII kiss code, secondary servers an IPv4 address.
func referenceIDString(stratum int, refID []byte) string {
	if stratum <= 1 {
		code := make([]byte, 0, 4)
		for _, b := range refID {
			if b >= 32 && b <= 126 {
				code = append(code, b)
			}
		}
		return string(code)
	}
	return net.IP(refID).String()
}

// fixedPoint16 decodes an NTP 16.16 fixed-point value into seconds.
func fixedPoint16(data []byte) float64 {
	whole := int32(binary.BigEndian.Uint16(data[0:2]))
	frac := binary.BigEndian.Uint16(data[2:4])
	return float64(whole) + float64(frac)/65536.0
}

// ntpTimeToTime converts an 8-byte NTP timestamp to a time.Time.
func ntpTimeToTime(data []byte) time.Time {
	seconds := binary.BigEndian.Uint32(data[0:4])
	fraction := binary.BigEndian.Uint32(data[4:8])
	if seconds == 0 && fraction == 0 {
		return time.Time{}
	}
	nsec := int64(fraction) * 1e9 / (1 << 32)
	return time.Unix(int64(seconds)-ntpEpochOffset, nsec).UTC()
}

// putNTPTime encodes a time.Time as an 8-byte NTP timestamp split into
// seconds and fraction parts.
func putNTPTime(secondsField, fractionField []byte, t time.Time) {
	seconds := uint32(t.Unix() + ntpEpochOffset)
	fraction := uint32(uint64(t.Nanosecond()) * (1 << 32) / 1e9)
	binary.BigEndian.PutUint32(secondsField, seconds)
	binary.BigEndian.PutUint32(fractionField, fraction)
}
