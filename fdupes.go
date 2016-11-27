// In this example we"ll look at how to implement
// a _worker pool_ using goroutines and channels.

package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"fmt"
	"github.com/lkwg82/fdupes/lib"
	"hash"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// TODO check mtime and ctime

var fileSizeMap = make(map[int64][]string)
var candidateCount = 0
var logger = lib.NewLog()

func walkTheTree(path string, info os.FileInfo, err error) error {

	if err != nil {
		fmt.Println(err)
		return nil
	}

	if info.IsDir() {
		return nil
	}

	isSymlink := func(path string) bool {
		linkedPath, _ := filepath.EvalSymlinks(path)
		return linkedPath != path
	}

	if isSymlink(path) {
		return nil
	}

	//fmt.Printf("reading file: %s\n", path)

	filesize := info.Size()
	if filesize == 0 {
		return nil
	}

	isHidden := func(path string) bool {
		return strings.Contains(path, string(filepath.Separator) + ".")
	}

	if isHidden(path) {
		return nil
	}

	if _, exists := fileSizeMap[filesize]; !exists {
		fileSizeMap[filesize] = []string{}
	}
	fileSizeMap[filesize] = append(fileSizeMap[filesize], path)
	candidateCount++

	return nil
}

func main() {
	if runtime.GOOS != "linux" {
		fmt.Println("sorry, need linux to run")
		os.Exit(1)
	}

	dir := "/backup/wirt.lgohlke.de/backup_from_others"

	logger.SetLevel(lib.WARN)

	logger.Info("walking the tree ...")
	if err := filepath.Walk(dir, walkTheTree); err != nil {
		logger.Fatal("", err)
	}

	pipeline := []func(bundle CandidatesBundle) CandidatesBundle{
		filterCandidateByFilesystemProperties,
		filterCandidateByFileType,
		filterCandidateByFirst4k,
		filterBigCandidatesByHashBlocks,
		filterCandidateByHash,
	}

	processListOfSameFilesizeCandidates(func(bundle CandidatesBundle) {
		logger.Info(" checking candidates with size: %d\n", bundle.filesize)

		for _, step := range pipeline {
			bundle = step(bundle)
			if bundle.isEmpty() {
				return
			}
		}
		doLinkingOfCandidates(bundle)
	})
}

type CandidatesBundle struct {
	filesize   int64
	candidates [][]string
}

func (cb *CandidatesBundle) isEmpty() bool {
	return len(cb.candidates) == 0
}

func filterBigCandidatesByHashBlocks(bundle CandidatesBundle) CandidatesBundle {
	if bundle.filesize > 10 * 1024 * 1024 {
		bundle = selectCandidateSame4kBlocks(bundle)
	}
	return bundle
}

func doLinkingOfCandidates(bundle CandidatesBundle) {
	for _, pair := range bundle.candidates {
		replaceDupesWithHardLinks(pair[0], pair[1])
	}
}

func filterCandidateByFileType(bundle CandidatesBundle) CandidatesBundle {
	newCandidates := make([][]string, 0)
	for _, pair := range bundle.candidates {
		if filepath.Ext(pair[0]) == filepath.Ext(pair[1]) {
			newCandidates = append(newCandidates, pair)
		}
	}
	return CandidatesBundle{filesize: bundle.filesize, candidates: newCandidates}
}

func replaceDupesWithHardLinks(path1, path2 string) {

	tempSuffix := ".fdupes.temp"
	if strings.HasSuffix(path1, tempSuffix) {
		return
	}
	if strings.HasSuffix(path2, tempSuffix) {
		return
	}

	info1, err := getSysStat(path1)
	if err != nil {
		log.Fatal(err)
	}

	info2, err := getSysStat(path2)
	if err != nil {
		log.Fatal(err)
	}

	if info1.Ino == info2.Ino {
		return
	}

	short := func(path string) string {
		return strings.Replace(path, "/backup/wirt.lgohlke.de/backup_from_others/backup_wilfried/bilder", "", 1)
	}

	newName := path2 + tempSuffix
	file, _ := os.Stat(newName)

	if file != nil {
		logger.Info("removing old %s", short(newName))
		if err := os.Remove(newName); err != nil {
			logger.Fatal("%s", err)
		}
	}
	logger.Info("create new link %s -> %s", short(newName), short(path1))
	if err := os.Link(path1, newName); err != nil {
		logger.Error("%s", err)
	}

	logger.Info("rename %s -> %s", short(newName), short(path2))
	if err := os.Rename(newName, path2); err != nil {
		logger.Error("ERROR: %s", err)
	}
}

func getSysStat(path string) (*syscall.Stat_t, error) {
	fileinfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := fileinfo.Sys().(*syscall.Stat_t)
	if !ok {
		logger.Fatal("Not a syscall.Stat_t")
	}
	return stat, nil
}

func filterCandidateByFilesystemProperties(bundle CandidatesBundle) CandidatesBundle {
	logger.Info("   filtering candidates with same properties ... \n")

	newCandidates := make([][]string, 0)
	for _, pair := range bundle.candidates {
		stat1, err1 := getSysStat(pair[0])
		stat2, err2 := getSysStat(pair[1])

		if err1 != nil {
			logger.Info("warning: %s (removing)", err1)
			continue
		}

		if err2 != nil {
			logger.Info("warning: %s (removing)", err2)
			continue
		}

		// do not process very fresh files
		secondsNow := time.Now().Unix()
		minDiff := int64(10)
		if (secondsNow - stat1.Ctim.Sec) < minDiff {
			continue
		}
		if (secondsNow - stat2.Ctim.Sec) < minDiff {
			continue
		}

		if stat1.Dev != stat2.Dev {
			continue
		}

		if stat1.Ino == stat2.Ino {
			if stat1.Nlink == 1 {
				logger.Info("WARNING: inodes equal: %s = %s ", pair[0], pair[1])
				continue
			}
			// already linked
			continue
		}

		if stat1.Gid != stat2.Gid {
			continue
		}

		if stat1.Uid != stat2.Uid {
			continue
		}

		newCandidates = append(newCandidates, pair)
	}
	return CandidatesBundle{filesize: bundle.filesize, candidates: newCandidates}
}

func filterCandidateByFirst4k(bundle CandidatesBundle) CandidatesBundle {
	logger.Info("   filtering candidates with same first 4k hash\n")
	newCandidates := make([][]string, 0)
	for _, pair := range bundle.candidates {
		h1, err1 := hashFirst4K(pair[0])
		h2, err2 := hashFirst4K(pair[1])

		if err1 != nil {
			logger.Info("warning: %s (removing)", err1)
			continue
		}

		if err2 != nil {
			logger.Info("warning: %s (removing)", err2)
			continue
		}

		if bytes.Equal(h1, h2) {
			newCandidates = append(newCandidates, pair)
		}
	}
	return CandidatesBundle{filesize: bundle.filesize, candidates: newCandidates}
}

func selectCandidateSame4kBlocks(bundle CandidatesBundle) CandidatesBundle {
	logger.Debug("   filtering candidates with same 4k blocks hash\n")

	partialHash := func(pair []string) bool {
		path1 := pair[0]
		file1, err := os.Open(path1)
		if err != nil {
			logger.Fatal(err.Error())
		}
		defer file1.Close()

		path2 := pair[1]
		file2, err := os.Open(path2)
		if err != nil {
			logger.Fatal(err.Error())
		}
		defer file2.Close()

		stat, err := file2.Stat()
		if err != nil {
			logger.Fatal(err.Error())
		}

		length := stat.Size()
		block := int64(length / int64(100))

		offsets := []int64{0, int64(length / 4), int64(length / 2), length - block}

		sameHash := true
		for _, offset := range offsets {
			if !sameHash {
				continue
			}

			if _, err := file1.Seek(offset, 0); err != nil {
				logger.Fatal(err.Error())
			}
			if _, err := file2.Seek(offset, 0); err != nil {
				logger.Fatal(err.Error())
			}

			validBlockSize := int64(math.Min(float64(block), float64(length)))
			h1, err1 := hashAt(file1, validBlockSize)
			h2, err2 := hashAt(file2, validBlockSize)

			if err1 != nil {
				logger.Info("warning: %s (removing)", err1)
				continue
			}

			if err2 != nil {
				logger.Info("warning: %s (removing)", err2)
				continue
			}

			sameHash = bytes.Equal(h1, h2)
			logger.Debug("  offset %d, same:%s, blocksize:%d ", offset, sameHash, block)
			logger.Debug("  offset %d, same:%s, blocksize:%d ", offset, sameHash, block)
		}

		return sameHash
	}

	newCandidates := make([][]string, 0)
	for _, pair := range bundle.candidates {
		if partialHash(pair) {
			newCandidates = append(newCandidates, pair)
		}
	}
	return CandidatesBundle{filesize: bundle.filesize, candidates: newCandidates}
}

func filterCandidateByHash(bundle CandidatesBundle) CandidatesBundle {
	logger.Info("   filtering candidates with same hash ... \n")
	newCandidates := make([][]string, 0)
	hashCache := make(map[string][]byte)
	for _, pair := range bundle.candidates {
		var h1, h2 []byte
		var err1, err2 error

		if _, exists := hashCache[pair[0]]; exists {
			h1, err1 = hashCache[pair[0]], nil
		} else {
			h1, err1 = hashFile(pair[0])
		}

		if _, exists := hashCache[pair[1]]; exists {
			h2, err2 = hashCache[pair[1]], nil
		} else {
			h2, err2 = hashFile(pair[1])
		}

		s1, _ := getSysStat(pair[0])
		s2, _ := getSysStat(pair[1])

		logger.Debug(" p %s", pair)
		logger.Debug("  h1: %x, size: %d", h1, s1.Size)
		logger.Debug("  h2: %x, size: %d", h2, s2.Size)

		if err1 != nil {
			logger.Info("warning: %s (removing)", err1)
			continue
		}

		if err2 != nil {
			logger.Info("warning: %s (removing)", err2)
			continue
		}

		if bytes.Equal(h1, h2) {
			newCandidates = append(newCandidates, pair)
		}
	}
	return CandidatesBundle{filesize: bundle.filesize, candidates: newCandidates}
}

func hashAt(file *os.File, blocksize int64) ([]byte, error) {
	data := make([]byte, blocksize)
	if _, err := file.ReadAt(data, 0); err != nil {
		return nil, err
	}
	return hashAlgo().Sum(data), nil
}

func hashAlgo() hash.Hash {
	return sha1.New()
}

func hashFirst4K(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY, 0666)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}

	length := int64(math.Min(float64(4 * 1024), float64(stat.Size())))
	data := make([]byte, length)
	if _, err := file.ReadAt(data, 0); err != nil {
		return nil, err
	}
	return hashAlgo().Sum(data), nil
}

func hashFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := bufio.NewReaderSize(file, 4 * 1024 * 1024)
	logger.Debug(" hashing %s", path)
	algo := hashAlgo()
	if _, err := io.Copy(algo, reader); err != nil {
		log.Fatal(err)
	}
	return algo.Sum(nil), nil
}

func processListOfSameFilesizeCandidates(candidatesHandler func(bundle CandidatesBundle)) {
	logger.Info("create list of candidates ... ")

	counter := 0
	for size, list := range fileSizeMap {
		logger.Info("---> progress %d/%d \n", counter, candidateCount)
		counter += len(list)
		if len(list) == 1 {
			continue
		}

		newCandidates := make([][]string, 0)
		for i := 0; i < (len(list) - 1); i++ {
			for j := 1; j < len(list); j++ {
				if i == j {
					continue
				}

				newCandidates = append(newCandidates, []string{list[i], list[j]})
			}
		}
		candidatesHandler(CandidatesBundle{filesize: size, candidates: newCandidates})
	}
}
