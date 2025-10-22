package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
)

type App struct {
	songs       []Song
	maxParallel uint64
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

		app.songs = append(app.songs, Song{Url: url})

	}

	CheckErr(scanner.Err())

}

func (app *App) processSongs() {
	songCount := len(app.songs)

	if songCount == 0 {
		return
	}

	fmt.Printf("Parallel limit %d\n", app.maxParallel)
	fmt.Printf("Processing %d songs...\n", songCount)

	var wg sync.WaitGroup
	wg.Add(songCount)
	limiter := make(chan struct{}, app.maxParallel)

	for _, song := range app.songs {
		limiter <- struct{}{}
		fmt.Printf("%s\n", song.Url)

		go func(song Song) {
			song.Process()
			wg.Done()
			<-limiter
		}(song)
	}

	wg.Wait()
}

func main() {
	var maxParallel uint64 = 1

	if len(os.Args) == 2 {
		providedMaxParallel, err := strconv.ParseUint(os.Args[1], 10, 32)

		CheckErr(err)

		if providedMaxParallel == 0 {
			CheckErr(errors.New("maxParallel has to be > 0"))
		}

		maxParallel = providedMaxParallel
	}

	app := App{maxParallel: maxParallel}
	app.loadFile("./list.txt")

	app.processSongs()
}
