package main

import (
	"fmt"
	"os/exec"
)

const bin = "yt-dlp.exe"
const args = "-f bestaudio -x --audio-format mp3 --audio-quality 0"

type Song struct {
	Url string
}

func (song *Song) Process() {
	fmt.Printf("Processing %s\n", song.Url)

	out, err := exec.Command(bin, "-f", "bestaudio", "-x", "--audio-format",
		"mp3", "--audio-quality", "0", song.Url).CombinedOutput()
	output := string(out)
	fmt.Println(output)

	CheckErr(err)

}
