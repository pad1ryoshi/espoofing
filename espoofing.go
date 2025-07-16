package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type DNSRecord struct {
	Domain string
	SPF    string
	DMARC  string
	SPFVuln bool
	DMARCVuln bool
}

type Scanner struct {
	threads int
	timeout time.Duration
	vulnFile *os.File
	vulnMutex sync.Mutex
}

func NewScanner(threads int, timeout time.Duration) *Scanner {
	// Cria arquivo para domínios vulneráveis
	vulnFile, err := os.Create("vuln-domains.txt")
	if err != nil {
		fmt.Printf("[-] Error to create vuln-domains.txt file: %v\n", err)
		vulnFile = nil
	}
	
	return &Scanner{
		threads: threads,
		timeout: timeout,
		vulnFile: vulnFile,
	}
}

func (s *Scanner) checkSPF(domain string) (string, bool) {
	// Busca registro TXT para SPF
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		return "", false
	}

	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=spf1") {
			// Verifica vulnerabilidades comuns no SPF
			vuln := s.analyzeSPF(record)
			return record, vuln
		}
	}
	return "", true // Sem SPF = vulnerável
}

func (s *Scanner) checkDMARC(domain string) (string, bool) {
	// DMARC é sempre em _dmarc.domain
	dmarcDomain := "_dmarc." + domain
	txtRecords, err := net.LookupTXT(dmarcDomain)
	if err != nil {
		return "", true // Sem DMARC = vulnerável
	}

	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=DMARC1") {
			// Verifica vulnerabilidades no DMARC
			vuln := s.analyzeDMARC(record)
			return record, vuln
		}
	}
	return "", true // Sem DMARC = vulnerável
}

func (s *Scanner) analyzeSPF(record string) bool {
	// Verifica configurações fracas no SPF
	vulnIndicators := []string{
		"~all",     // SoftFail - permite spoofing
		"+all",     // Pass - permite qualquer IP
		"?all",     // Neutral - não faz verificação
		"redirect", // Pode ser mal configurado
	}

	record = strings.ToLower(record)
	
	// Se não termina com -all, é vulnerável
	if !strings.Contains(record, "-all") {
		return true
	}

	// Verifica outros indicadores de vulnerabilidade
	for _, indicator := range vulnIndicators {
		if strings.Contains(record, indicator) {
			return true
		}
	}

	return false
}

func (s *Scanner) analyzeDMARC(record string) bool {
	record = strings.ToLower(record)
	
	// Verifica políticas fracas
	if strings.Contains(record, "p=none") {
		return true // Política "none" não rejeita emails
	}
	
	// Verifica se não tem política definida
	if !strings.Contains(record, "p=quarantine") && !strings.Contains(record, "p=reject") {
		return true
	}

	// Verifica porcentagem baixa
	if strings.Contains(record, "pct=") {
		// Se especifica porcentagem, pode ser vulnerável se for muito baixa
		if strings.Contains(record, "pct=0") || strings.Contains(record, "pct=1") {
			return true
		}
	}

	return false
}

func (s *Scanner) saveVulnerableDomain(domain string) {
	if s.vulnFile == nil {
		return
	}
	
	s.vulnMutex.Lock()
	defer s.vulnMutex.Unlock()
	
	_, err := s.vulnFile.WriteString(domain + "\n")
	if err != nil {
		fmt.Printf("[-] Error to save the vulnerable domain: %v\n", err)
	}
}

func (s *Scanner) scanDomain(domain string) DNSRecord {
	domain = strings.TrimSpace(domain)
	
	record := DNSRecord{
		Domain: domain,
	}

	// Verifica SPF
	spf, spfVuln := s.checkSPF(domain)
	record.SPF = spf
	record.SPFVuln = spfVuln

	// Verifica DMARC
	dmarc, dmarcVuln := s.checkDMARC(domain)
	record.DMARC = dmarc
	record.DMARCVuln = dmarcVuln

	return record
}

func (s *Scanner) scanFromFile(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("[-] Error to open the file: %v\n", err)
		return
	}
	defer file.Close()

	// Canal para domínios
	domains := make(chan string, 100)
	results := make(chan DNSRecord, 100)
	
	// WaitGroup para threads
	var wg sync.WaitGroup

	// Inicia workers
	for i := 0; i < s.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range domains {
				result := s.scanDomain(domain)
				results <- result
			}
		}()
	}

	// Goroutine para exibir resultados
	go func() {
		for result := range results {
			s.printResult(result)
		}
	}()

	// Lê domínios do arquivo
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" {
			domains <- domain
		}
	}

	close(domains)
	wg.Wait()
	close(results)
	
	// Fecha arquivo de domínios vulneráveis
	if s.vulnFile != nil {
		s.vulnFile.Close()
	}
}

func (s *Scanner) printResult(record DNSRecord) {
	fmt.Printf("\n[*] Domain: %s\n", record.Domain)
	
	// SPF Status
	if record.SPF == "" {
		fmt.Printf("    SPF: %s[NOT FOUND - VULNERABLE]%s\n", "\033[31m", "\033[0m")
	} else {
		status := "OK"
		color := "\033[32m"
		if record.SPFVuln {
			status = "VULNERABLE"
			color = "\033[31m"
		}
		fmt.Printf("    SPF: %s[%s]%s\n", color, status, "\033[0m")
		fmt.Printf("         %s\n", record.SPF)
	}

	// DMARC Status
	if record.DMARC == "" {
		fmt.Printf("    DMARC: %s[NOT FOUND - VULNERABLE]%s\n", "\033[31m", "\033[0m")
	} else {
		status := "OK"
		color := "\033[32m"
		if record.DMARCVuln {
			status = "VULNERABLE"
			color = "\033[31m"
		}
		fmt.Printf("    DMARC: %s[%s]%s\n", color, status, "\033[0m")
		fmt.Printf("           %s\n", record.DMARC)
	}

	// Resumo da vulnerabilidade
	if record.SPFVuln || record.DMARCVuln {
		fmt.Printf("    %s[!] SPOOFING POSSIBLE%s\n", "\033[33m", "\033[0m")
		// Salva domínio vulnerável no arquivo
		s.saveVulnerableDomain(record.Domain)
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: espoofing <domains_file> [threads] [timeout]")
		fmt.Println("Example: espoofing subdomains.txt 50 5")
		os.Exit(1)
	}

	filename := os.Args[1]
	threads := 20
	timeout := 5 * time.Second

	// Parse argumentos opcionais
	if len(os.Args) > 2 {
		fmt.Sscanf(os.Args[2], "%d", &threads)
	}
	if len(os.Args) > 3 {
		var timeoutSec int
		fmt.Sscanf(os.Args[3], "%d", &timeoutSec)
		timeout = time.Duration(timeoutSec) * time.Second
	}

	fmt.Printf("[+] SPF/DMARC Scanner - Email Spoofing Vulnerability Checker\n")
	fmt.Printf("[+] Threads: %d, Timeout: %v\n", threads, timeout)
	fmt.Printf("[+] Scanning domains from: %s\n", filename)
	fmt.Printf("[+] Vulnerable domains will be saved to: vuln-domains.txt\n")
	fmt.Println(strings.Repeat("-", 60))

	scanner := NewScanner(threads, timeout)
	scanner.scanFromFile(filename)
	
	fmt.Printf("\n[+] Scan completed! Check vuln-domains.txt for vulnerable domains.\n")
}
