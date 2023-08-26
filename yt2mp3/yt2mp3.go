package main

import (
	"bufio"
	"fmt"
	"os"
)

type App struct {
	songs []Song
}

func (app *App) loadFile(path string) {
	file, err := os.Open(path)

	CheckErr(err)
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		if len(line) < 20 {
			continue
		}

		url := ExtractVideoUrl(line)

		app.songs = append(app.songs, Song{url: url})

	}

	CheckErr(scanner.Err())

}

func (app *App) processSongs() {
	songCount := len(app.songs)

	if songCount == 0 {
		return
	}

	fmt.Printf("Processing %d songs...\n", songCount)

	for _, song := range app.songs {
		fmt.Println(song)
	}
}

func main() {
	app := App{}
	app.loadFile("./list.txt")

	app.processSongs()
}
