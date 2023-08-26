package main

import (
	"log"
	"regexp"
)

var urlRegex = regexp.MustCompile(`(\S+v=.+?)(\&|\s*$)`)

func ExtractVideoUrl(line string) string {

	if urlRegex.MatchString(line) {
		return urlRegex.FindStringSubmatch(line)[1]
	}

	return ""
}

func CheckErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
