package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

/*SrcDir Меняем в CLI, либо в flag value*/
type settings struct {
	SRCDIR       string
	SignDir      string
	ReportDir    string
	WhitelistDir string
}

type Sig struct {
	signature string
	isWhite   bool
}

type Signs struct {
	PathName string
	Sigs     []Sig
}

var ResSlice []Result

type Result struct {
	LineNum   []string
	Path      []string
	Sign      []string
	Line      []string
	filename  string
	Whitelist []bool
}

var res = Result{}

func (res *Result) PrintInfoToConsole() {
	for i := range res.LineNum {
		log.Println(res.LineNum[i] + " " + res.Path[i] + " " + "Sign: " + res.Sign[i] + " " + "Line: " + res.Line[i])
	}
}

func (res *Result) PrintToFile(file *os.File) {
	_, err := file.Write([]byte(`<!DOCTYPE html>
	<html lang="en">
	<head>
	<meta charset="UTF-8">
	<title>Report</title>
	<style>
       table,th,td {
           border: 1px solid grey
        }
    </style>
	<table>
	<th> №Line </th>
    <th> Path </th>
    <th>  Sign </th>
    <th>  Line </th>
	<th>  isWhite? </th>`))
	if err != nil {
		log.Fatal("Error writing HTMl header:", err)
	}

	for i := range res.LineNum {
		if _, err := file.Write([]byte(`<tr>`)); err != nil {
			log.Fatal(err)
		}
		if len(res.Line[i]) > 100 {
			res.Line[i] = res.Line[i][:100]
		}
		if _, err := file.WriteString(
			"<td>" + res.LineNum[i] + "</td>" +
				"<td>" + res.Path[i] + "</td>" +
				"<td>" + res.Sign[i] + "</td>" +
				"<td>" + res.Line[i] + "</td>" +
				"<td>" + strconv.FormatBool(res.Whitelist[i]) + "</td>" + "\n"); err != nil {
			log.Fatal(err)
		}
		if _, err := file.Write([]byte(`</tr>`)); err != nil {
			log.Fatal(err)
		}
		if res.Whitelist[i] == false {
			log.Printf("finded not whitelist function at line %s  path:%s \n sign:%s \n",
				res.LineNum[i], res.Path[i], res.Sign[i])
		}
	}
	if _, err := file.Write([]byte(`</table></head><body></body></html>`)); err != nil {
		log.Fatal(err)
	}

}

func (res *Result) Add(tmpLnNum string, tmpPath string, tmpLine string, sig Sig, filename string) {
	res.LineNum = append(res.LineNum, tmpLnNum)
	res.Path = append(res.Path, tmpPath)
	res.Line = append(res.Line, tmpLine)
	res.Sign = append(res.Sign, sig.signature)
	res.Whitelist = append(res.Whitelist, sig.isWhite)
	res.filename = filename
}

func (res *Result) Clear() {
	res.LineNum = res.LineNum[:0]
	res.Path = res.Path[:0]
	res.Line = res.Line[:0]
	res.Sign = res.Sign[:0]
}

// WalkDirGetPaths -- проходит по списку файлов в указанной директории и извлекает пути к  файлам
func WalkDirGetPaths(path string) (FilesPaths []string) {
	err := filepath.Walk(path,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				log.Fatal("Error walking signatures dir:", err)
				return err
			}
			//Если директория - выводим название
			if info.IsDir() {
				fmt.Printf("[%s]\n", path)
			} else { //Если файл, обрабатываем
				FilesPaths = append(FilesPaths, path)
			}
			return nil
		})
	if err != nil {
		log.Println("Error through filepath walk in WALK-DIR fn:", err)
	}
	return FilesPaths
}

//ProcessSignFile -- Извлекает из файлов  сигнатуры и записывает их в структуру Signs
// Если не установлен флаг needWL, по умолчанию пишется значение false
func ProcessSignFile(path string, setting settings, needWL bool) (s Signs) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatal("Error through opening signatures file:", err)
	}
	s.PathName = path

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		//Обрабатываем комментарии в файлах-сигнатурах
		if strings.HasPrefix(scanner.Text(), "//") {
			continue
		} else {
			sign := scanner.Text()
			isWhite := false
			//log.Println("Process Sign: ", Sign)
			if needWL {
				isWhite = IsSignWhiteListed(WalkDirGetPaths(setting.WhitelistDir), sign)
			}
			s.Sigs = append(s.Sigs, Sig{
				signature: sign,
				isWhite:   isWhite,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal("Error through scanner in ProcessSign fn:", err)
	}
	if file.Close() != nil {
		log.Fatal("error closing the file: ", err)
	}
	return s
}

//IsSignWhiteListed -- проверяет входит ли сигнатура в белый список.
func IsSignWhiteListed(WhiteListsFilesPaths []string, sign string) (isWhite bool) {
	for _, p := range WhiteListsFilesPaths {
		f, err := os.Open(p)
		if err != nil {
			log.Fatal("Error through opening signatures file:", err)
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			text := sc.Text()
			if sign != text {
				continue
			} else {
				isWhite = true
				break
			}
		}
	}
	return isWhite
}

// WalkDirSRC -- исследует имеющиеся сигнатуры Signs в директории SRC_DIR из settings.
// Игнорирует расширения ignoreExtList
func WalkDirSRC(signsCh chan Signs, wg *sync.WaitGroup, ignoreExtList []string, setting settings) {
	defer close(signsCh)
	for sign := range signsCh {
		signs := sign
		fmt.Println("Processing Sign-file: ", signs.PathName)
		CreateIfNotExistReportDir(setting)
		//Split Sign.Name to confirm directory(folder)
		reportFile, err := CreateOpenReportFile(signs, setting)
		//Process every file in src directory except ignored extensions
		err = filepath.Walk(setting.SRCDIR,
			func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() || IsIgnoredFile(path, ignoreExtList) {
				} else { //Если файл, обрабатываем
					f, err := os.Open(path)
					if err != nil {
						log.Fatal("Error opening file: ", path, "Error: ", err)
					}
					scanner := bufio.NewScanner(f)
					//Увеличиваем размер буфера, замедляет программу на ~ 30 % по бенчмаркам,
					const maxCapacity = 65536 * 160
					buf := make([]byte, maxCapacity)
					scanner.Buffer(buf, maxCapacity)
					line := 1
					for scanner.Scan() {
						tmp := scanner.Text()
						//If source line contains sign,add to result struct
						for _, sig := range signs.Sigs {
							if strings.Contains(tmp, sig.signature) {
								//log.Println("FINDER: ", line, ":", Path, "Line:", scanner.Text())
								res.Add(strconv.Itoa(line), path, scanner.Text(), sig, reportFile.Name())
								//report_file.WriteString(strconv.Itoa(line) + " " + Path + " " + "Sign: " + Sign + " " + "Line: " + scanner.Text() + "\n")
							}
						}
						line++
					}
					if err := scanner.Err(); err != nil {
						log.Fatal("Error through Scanner in WalkDirSRC fn: ", err)
					}
					if err := f.Close(); err != nil {
						log.Fatal("Err;", err)
					}
				}
				return nil
			})
		if err != nil {
			log.Println(err)
		}
		res.PrintToFile(reportFile)
		ResSlice = append(ResSlice, res)
		res.Clear()
		fmt.Println("Ended:", sign.PathName)
		if err := reportFile.Close(); err != nil {
			log.Fatal("Error closing file:", err)
		}
		wg.Done()
	}

}

//IsIgnoredFile -- узнает является ли расширение файла игнорируемым
func IsIgnoredFile(path string, ignoreExtList []string) bool {
	IsIgnored := false
	for _, ext := range ignoreExtList {
		if filepath.Ext(path) == ext {
			IsIgnored = true
			break
		}
	}
	return IsIgnored
}

//CreateOpenReportFile -- создает и открывает файл отчета для сигнатуры
func CreateOpenReportFile(signs Signs, setting settings) (*os.File, error) {
	path := strings.Split(signs.PathName, "\\")
	reportFile, err := os.OpenFile(setting.ReportDir+"\\"+path[1]+".html", os.O_CREATE|os.O_RDWR, 0777)
	if err != nil {
		log.Panic("\t", signs.PathName, "\n", err)
	}
	return reportFile, err
}

//CreateIfNotExistReportDir -- Создает директорию для отчета
//TODO:Передавать непосредственно dir отчета?
func CreateIfNotExistReportDir(setting settings) {
	//Если нет директории для создания отчета
	if _, err := os.Stat(setting.ReportDir); os.IsNotExist(err) {
		if err := os.Mkdir(setting.ReportDir, 0777); err != nil {
			log.Fatal("Cant create dir:", err)
		}
	}
}

func main() {
	setting := settings{}
	flag.StringVar(&setting.SRCDIR, "SRC_DIR", "./Source", "Директория исходных файлов исследуемого ПО")
	flag.StringVar(&setting.SignDir, "SIGN_DIR", "./SignsCrypto", "Директория файлов-сигнатур ПО")
	flag.StringVar(&setting.ReportDir, "REPORT_DIR", "./Report", "Директория для формирования отчета")
	flag.StringVar(&setting.WhitelistDir, "CP5", "./CP5TestSigns", "Директория для файлов сигнатур WL")
	flag.String("help", "help", "ПО предназначено для ОВ на ОС СН, при задание дополнительных аргументов,относительные пути начинаются в unix-style через ./")
	flag.Parse()
	var signs []Signs
	ignoreExtList := []string{".dll", ".dcu", ".dcp", ".so", ".exe", ".map", ".pas", ".dbg", ".7z", ".rar", ".bpl"}
	//Get Signs structs slice from files in SIGN_DIR
	for _, SignFile := range WalkDirGetPaths(setting.SignDir) {
		signs = append(signs, ProcessSignFile(SignFile, setting, true))
	}

	//Process every Sign with report in Report_dir
	var signCh = make(chan Signs, 20)
	var wg sync.WaitGroup

	for _, sign := range signs {
		wg.Add(1)
		signCh <- sign
	}
	go WalkDirSRC(signCh, &wg, ignoreExtList, setting)
	wg.Wait()

}
