/*
 * This file was last modified at 2025-03-06 17:18 by Victor N. Skurikhin.
 * This is free and unencumbered software released into the public domain.
 * For more information, please refer to <http://unlicense.org>
 * handler_json.go
 * $Id$
 */

// This program SNMP BulkWalk.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/vskurikhin/gosnmp-sw-raid/internal/collector"
)

func main() {
	flag.Usage = func() {
		fmt.Printf("Usage:\n")
		fmt.Printf("   %s [-c=<community>] [-c=<host>]\n", filepath.Base(os.Args[0]))
		fmt.Printf("     host      - the host to walk/scan\n")
		flag.PrintDefaults()
	}

	var community string
	flag.StringVar(&community, "c", "public", "the community string for device")
	var host string
	flag.StringVar(&host, "h", "127.0.0.1", "the host string for device")
	flag.Parse()

	gosnmp.Default.Target = host
	gosnmp.Default.Community = community
	gosnmp.Default.Timeout = time.Duration(5 * time.Second) // Timeout better suited to walking
	gosnmp.Default.Retries = 5
	err := gosnmp.Default.Connect()
	if err != nil {
		fmt.Printf("Connect err: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = gosnmp.Default.Conn.Close() }()

	c := collector.New(collector.Config{
		SwRaidIndex: ".1.3.6.1.4.1.2021.13.18.1.1.1",
		SwRaidOIDs: []string{
			".1.3.6.1.4.1.2021.13.18.1.1.2",
			".1.3.6.1.4.1.2021.13.18.1.1.3",
			".1.3.6.1.4.1.2021.13.18.1.1.4",
			".1.3.6.1.4.1.2021.13.18.1.1.5",
		},
		SwRaidStatus: ".1.3.6.1.4.1.2021.13.18.1.1.6",
	})
	err = gosnmp.Default.BulkWalk(c.SwRaidIndex(), c.CollectIndexes)
	if err != nil {
		fmt.Printf("Walk Error: %v\n", err)
		os.Exit(1)
	}
	for _, o := range c.Oids() {
		err = gosnmp.Default.BulkWalk(o, c.CollectValues)
		if err != nil {
			fmt.Printf("Walk Error: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf(c.Sprint())
	if !c.Status() {
		os.Exit(1)
	}
}
