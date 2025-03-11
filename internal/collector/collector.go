package collector

import (
	"bytes"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strconv"

	"github.com/gosnmp/gosnmp"
)

var re, _ = regexp.Compile(`.*\d+\.(\d+)$`)

type Collector interface {
	CollectIndexes(pdu gosnmp.SnmpPDU) error
	CollectValues(pdu gosnmp.SnmpPDU) error
	Oids() []string
	Sprint() string
	Status() bool
	SwRaidIndex() string
	SwRaidOIDs() []string
	SwRaidStatus() string
}

type Config struct {
	SwRaidIndex  string
	SwRaidOIDs   []string
	SwRaidStatus string
}

type value struct {
	goSNMPType gosnmp.Asn1BER
	oid        string
	value      any
}

type values struct {
	Values []value
	Status bool
}

type collector struct {
	swRaidIndex  string
	swRaidOIDs   []string
	swRaidStatus string
	state        map[int64]values
	status       bool
}

func New(cfg Config) Collector {
	return &collector{
		swRaidIndex:  cfg.SwRaidIndex,
		swRaidOIDs:   cfg.SwRaidOIDs,
		swRaidStatus: cfg.SwRaidStatus,
		state:        make(map[int64]values),
	}
}

func (c collector) SwRaidIndex() string {
	return c.swRaidIndex
}

func (c collector) SwRaidOIDs() []string {
	return c.swRaidOIDs
}

func (c collector) SwRaidStatus() string {
	return c.swRaidStatus
}

func (c collector) State() map[int64]values {
	return c.state
}

func (c collector) Oids() []string {
	result := make([]string, len(c.swRaidOIDs)+1)
	copy(result, c.swRaidOIDs)
	result[len(c.swRaidOIDs)] = c.swRaidStatus
	return result
}

func (c *collector) Status() bool {
	status := true
	keys := c.keys()
	for _, i := range keys {
		status = status && c.state[i].Status
	}
	c.status = status
	return c.status
}

func (c collector) Sprint() string {
	keys := c.keys()
	status := c.Status()
	var buffer bytes.Buffer
	if status {
		buffer.WriteString("OK")
	} else {
		buffer.WriteString("FAIL")
	}
	if len(keys) > 0 {
		buffer.WriteString(" ")
	}
	for j, i := range keys {
		buffer.Write(c.valuesToBytes(i))
		if len(keys) > (j + 1) {
			buffer.WriteString("; ")
		}
	}
	return buffer.String()
}

func (c *collector) CollectIndexes(pdu gosnmp.SnmpPDU) error {

	switch pdu.Type {
	case gosnmp.Integer:
		i := gosnmp.ToBigInt(pdu.Value).Int64()
		slog.Debug("collect: ", pdu.Name, i)
		c.state[i] = values{Values: make([]value, 0, 0)}
	default:
		e := fmt.Errorf("unknown index type: %d", pdu.Type)
		slog.Info(" ", e)
		return e
	}
	return nil
}

func (c *collector) CollectValues(pdu gosnmp.SnmpPDU) error {
	res := re.FindAllStringSubmatch(pdu.Name, -1)
	if len(res) > 0 && len(res[0]) > 1 {
		err := c.collectValues(pdu, res[0][1])
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *collector) collectValues(pdu gosnmp.SnmpPDU, sIndex string) error {
	i, err := strconv.ParseInt(sIndex, 10, 64)
	if err != nil {
		return err
	}
	vs := c.state[i].Values
	vx := value{oid: pdu.Name, goSNMPType: pdu.Type, value: pdu.Value}
	vs = append(vs, vx)
	if k, ok := pdu.Value.(int); ok {
		if pdu.Name == c.swRaidStatusConcatIndex(sIndex) {
			status := k == 2
			c.state[i] = values{Values: vs, Status: status}
		}
	} else {
		c.state[i] = values{Values: vs, Status: c.state[i].Status}
	}
	return nil
}

func (c collector) keys() []int64 {
	result := make([]int64, len(c.state))
	i := 0
	for k := range c.state {
		result[i] = k
		i++
	}
	slices.Sort(result)
	return result
}

func (c collector) valuesToBytes(i int64) []byte {
	var buffer bytes.Buffer
	for l, v := range c.state[i].Values {
		switch v.goSNMPType {
		case gosnmp.Integer:
			buffer.WriteString(gosnmp.ToBigInt(v.value).String())
		case gosnmp.OctetString:
			buffer.WriteString(string(v.value.([]byte)))
		default:
			buffer.WriteString(fmt.Sprintf("%v", v.value))
		}
		if len(c.state[i].Values) > (l + 1) {
			buffer.WriteString(", ")
		}
	}
	return buffer.Bytes()
}

func (c *collector) swRaidStatusConcatIndex(sIndex string) string {
	var buffer bytes.Buffer
	buffer.WriteString(c.swRaidStatus)
	buffer.WriteRune('.')
	buffer.WriteString(sIndex)
	return buffer.String()
}
