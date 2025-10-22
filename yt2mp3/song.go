package main

import (
	"fmt"
	"log"
	"os/exec"
)

const bin = "yt-dlp.exe"

type Song struct {
	Url string
}

func (song *Song) Process() {
	fmt.Printf("Processing %s\n", song.Url)

	cmd := exec.Command(bin, "-f", "bestaudio", "-x", "--audio-format",
		"mp3", "--audio-quality", "0", song.Url)

	fmt.Printf("CMD: %s\n", cmd)

	stdout, err := cmd.StdoutPipe()
	CheckErr(err)

	err = cmd.Start()
	CheckErr(err)

	buff := make([]byte, 64)
	var n int

	for err == nil {
		n, err = stdout.Read(buff)

		if n > 0 {
			fmt.Print(string(buff[:n]))
		}
	}

	cmd.Wait()

	if !cmd.ProcessState.Success() {
		log.Fatal("Song process failed")
	}
}
