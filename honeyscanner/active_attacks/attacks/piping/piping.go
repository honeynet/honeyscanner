package piping

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"attacks/structs"
)

const PIPEPATH string = "/tmp/data"

func jsonParse(line string) (*structs.Data, error) {
	// Parse the JSON data
	var data structs.Data
	err := json.Unmarshal([]byte(line), &data)
	if checkError(err) {
		return nil, err
	}
	return &data, nil
}

func OpenPipe() (*os.File, error) {
	pipe, err := os.OpenFile(PIPEPATH, os.O_RDWR|os.O_SYNC, os.ModeNamedPipe)
	if checkError(err) {
		return nil, err
	}
	return pipe, nil
}

func ReadData(pipe *os.File) (*structs.Data, error) {
	reader := bufio.NewReader(pipe)
	line, err := reader.ReadString('\n')
	if checkError(err) {
		return nil, err
	}
	data, err := jsonParse(line)
	if checkError(err) {
		return nil, err
	}
	return data, nil
}

func WriteData(pipe *os.File, results *structs.Results) error {
	resultBytes, err := json.Marshal(results)
	if checkError(err) {
		return err
	}
	writer := bufio.NewWriter(pipe)
	time.Sleep(30 * time.Millisecond)
	writer.Write(resultBytes)
	writer.Write([]byte("\n"))
	err = writer.Flush()
	if checkError(err) {
		return err
	}
	return nil
}

func checkError(err error) bool {
	if err != nil {
		fmt.Println("Error with OS pipe: ", err)
		return true
	}
	return false
}
