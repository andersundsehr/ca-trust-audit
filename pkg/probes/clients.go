package probes

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/andersundsehr/ca-trust-audit/pkg/certificates"
	"github.com/andersundsehr/ca-trust-audit/pkg/report"
)

// Result contains only normalized categories and certificate identities, never
// raw runtime output, URL credentials, proxy addresses or exception messages.
type Result struct {
	RootName                   string
	RootSHA256                 string
	VerifiedIntermediateSHA256 string
	Status                     report.Status
	Category                   string
	LeafSHA256                 string
}

// Probe is the extension point for additional clients. A successful TLS request
// is not enough: accepted peers must be identified by their certificate hash.
type Probe interface {
	Name() string
	Discover(context.Context, Runner) bool
	Check(context.Context, Runner, string) Result
}
type Native struct{ Transport *http.Transport }

func (Native) Name() string                          { return "Go TLS (scanner)" }
func (Native) Discover(context.Context, Runner) bool { return true }
func (n Native) Check(ctx context.Context, _ Runner, endpoint string) Result {
	tr := n.Transport
	if tr == nil {
		tr = &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 10 * time.Second}
		defer tr.CloseIdleConnections()
	}
	client := http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if e != nil {
		return Result{Status: report.Inconclusive, Category: "invalid_endpoint"}
	}
	req.Header.Set("User-Agent", "ca-trust-audit/1")
	res, e := client.Do(req)
	if e != nil {
		var cv *tls.CertificateVerificationError
		if errors.As(e, &cv) {
			return Result{Status: report.Rejected, Category: "certificate_validation"}
		}
		var dns *net.DNSError
		if errors.As(e, &dns) {
			return Result{Status: report.Inconclusive, Category: "dns"}
		}
		var ne net.Error
		if errors.Is(e, context.DeadlineExceeded) || (errors.As(e, &ne) && ne.Timeout()) {
			return Result{Status: report.Inconclusive, Category: "timeout"}
		}
		return Result{Status: report.Inconclusive, Category: "connection_or_proxy"}
	}
	defer res.Body.Close()
	if res.TLS == nil || len(res.TLS.VerifiedChains) == 0 || len(res.TLS.PeerCertificates) == 0 {
		return Result{Status: report.Inconclusive, Category: "unverified_response"}
	}
	verified := res.TLS.VerifiedChains[0]
	root := verified[len(verified)-1]
	result := Result{Status: report.VulnerableClient, Category: "tls_accepted", LeafSHA256: certificates.SHA256(res.TLS.PeerCertificates[0].Raw), RootName: root.Subject.CommonName, RootSHA256: certificates.SHA256(root.Raw)}
	if len(verified) > 1 {
		result.VerifiedIntermediateSHA256 = certificates.SHA256(verified[1].Raw)
	}
	return result
}

type Script struct {
	Label, Executable string
	Discovery         []string
	Prefix            []string
	Source            string
}

func (s Script) Name() string { return s.Label }
func (s Script) Discover(ctx context.Context, r Runner) bool {
	return Exists(ctx, r, s.Executable, s.Discovery...)
}
func (s Script) Check(ctx context.Context, r Runner, endpoint string) Result {
	args := append(append([]string{}, s.Prefix...), s.Source, endpoint)
	b, e := r.Run(ctx, s.Executable, args...)
	if ctx.Err() != nil {
		return Result{Status: report.Inconclusive, Category: "timeout_or_canceled"}
	}
	if e != nil {
		return Result{Status: report.Inconclusive, Category: "execution_failed"}
	}
	return ParseResult(string(b))
}

// ParseResult accepts exactly one protocol line, so warnings and malformed client
// responses cannot accidentally become successful security checks.
func ParseResult(s string) Result {
	f := strings.Fields(strings.TrimSpace(s))
	bad := Result{Status: report.Inconclusive, Category: "malformed_response"}
	if len(f) != 3 || f[0] != "CTA1" {
		return bad
	}
	switch f[1] {
	case "ACCEPT":
		if len(f[2]) != 64 {
			return bad
		}
		for _, c := range f[2] {
			if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
				return bad
			}
		}
		return Result{Status: report.VulnerableClient, Category: "tls_accepted", LeafSHA256: strings.ToLower(f[2])}
	case "REJECT":
		if f[2] == "certificate_validation" {
			return Result{Status: report.Rejected, Category: f[2]}
		}
	case "ERROR":
		switch f[2] {
		case "dns", "timeout", "connection_or_proxy", "identity_unavailable", "unsafe_configuration", "runtime_error":
			return Result{Status: report.Inconclusive, Category: f[2]}
		}
	}
	return bad
}

type Curl struct{}

func (Curl) Name() string                                { return "curl" }
func (Curl) Discover(ctx context.Context, r Runner) bool { return Exists(ctx, r, "curl", "--version") }
func (Curl) Check(ctx context.Context, r Runner, endpoint string) Result {
	// -q must be first: a curlrc may contain insecure or output-writing directives.
	b, _ := r.Run(ctx, "curl", "-q", "--silent", "--show-error", "--max-time", "10", "--proto", "=https", "--output", "/dev/null", "--write-out", "\nCTA_CURL %{exitcode} %{http_code}\n%{certs}", endpoint)
	if ctx.Err() != nil {
		return Result{Status: report.Inconclusive, Category: "timeout_or_canceled"}
	}
	return ParseCurl(b)
}
func ParseCurl(b []byte) Result {
	s := string(b)
	pos := strings.Index(s, "\nCTA_CURL ")
	if pos < 0 {
		return Result{Status: report.NotSupported, Category: "curl_requires_certinfo"}
	}
	line, rest, _ := strings.Cut(s[pos+1:], "\n")
	f := strings.Fields(line)
	if len(f) != 3 {
		return Result{Status: report.Inconclusive, Category: "malformed_response"}
	}
	code, e := strconv.Atoi(f[1])
	if e != nil {
		return Result{Status: report.Inconclusive, Category: "malformed_response"}
	}
	if code == 60 {
		return Result{Status: report.Rejected, Category: "certificate_validation"}
	}
	if code != 0 {
		category := "connection_or_proxy"
		if code == 5 || code == 6 {
			category = "dns"
		}
		if code == 28 {
			category = "timeout"
		}
		return Result{Status: report.Inconclusive, Category: category}
	}
	start := strings.Index(rest, "-----BEGIN CERTIFICATE-----")
	end := strings.Index(rest, "-----END CERTIFICATE-----")
	if start < 0 || end < start {
		return Result{Status: report.NotSupported, Category: "peer_identity_unavailable"}
	}
	cs, e := certificates.ParsePEM([]byte(rest[start : end+len("-----END CERTIFICATE-----")]))
	if e != nil {
		return Result{Status: report.Inconclusive, Category: "malformed_response"}
	}
	return Result{Status: report.VulnerableClient, Category: "tls_accepted", LeafSHA256: certificates.SHA256(cs[0].Raw)}
}

// Defaults returns clients with safe in-memory execution support. Java is reported
// separately as unsupported: JSSE has no portable read-only inline execution mode.
func Defaults() []Probe {
	return []Probe{
		Curl{},
		Script{"Python ssl/urllib", "python3", []string{"-B", "-c", "import ssl,urllib.request"}, []string{"-B", "-c"}, pythonSSL},
		Script{"Python requests/certifi", "python3", []string{"-B", "-c", "import requests,certifi"}, []string{"-B", "-c"}, pythonRequests},
		Script{"Node.js HTTPS", "node", []string{"--version"}, []string{"-e"}, nodeHTTPS},
		Script{"PHP OpenSSL streams", "php", []string{"-r", "exit(extension_loaded('openssl')?0:1);"}, []string{"-r"}, phpSSL},
		Script{"PHP cURL", "php", []string{"-r", "exit(extension_loaded('curl')?0:1);"}, []string{"-r"}, phpCurl},
		Script{"Ruby HTTPS", "ruby", []string{"-e", "require 'net/http'; require 'openssl'"}, []string{"-e"}, rubyHTTPS},
	}
}

const pythonSSL = `import ssl,urllib.request,urllib.error,socket,hashlib,sys
try:
 r=urllib.request.urlopen(urllib.request.Request(sys.argv[1],headers={'User-Agent':'ca-trust-audit/1'}),timeout=10)
except urllib.error.HTTPError as e:
 r=e
except Exception as e:
 reason=getattr(e,'reason',e)
 print('CTA1 REJECT certificate_validation' if isinstance(reason,ssl.SSLCertVerificationError) else 'CTA1 ERROR '+('dns' if isinstance(reason,socket.gaierror) else 'timeout' if isinstance(reason,(TimeoutError,socket.timeout)) else 'connection_or_proxy'))
 sys.exit(0)
try:
 cert=r.fp.raw._sock.getpeercert(binary_form=True)
 print('CTA1 ACCEPT '+hashlib.sha256(cert).hexdigest())
except Exception:
 print('CTA1 ERROR identity_unavailable')
finally:
 r.close()
`
const pythonRequests = `import requests,certifi,hashlib,sys
try:
 r=requests.get(sys.argv[1],timeout=10,stream=True,allow_redirects=False,headers={'User-Agent':'ca-trust-audit/1'})
 try:
  sock=r.raw.connection.sock
  if sock is None: sock=r.raw._fp.fp.raw._sock
  print('CTA1 ACCEPT '+hashlib.sha256(sock.getpeercert(binary_form=True)).hexdigest())
 except Exception: print('CTA1 ERROR identity_unavailable')
 finally: r.close()
except requests.exceptions.SSLError as e:
 print('CTA1 REJECT certificate_validation' if 'CERTIFICATE_VERIFY_FAILED' in str(e) else 'CTA1 ERROR connection_or_proxy')
except requests.exceptions.Timeout: print('CTA1 ERROR timeout')
except Exception: print('CTA1 ERROR connection_or_proxy')
`
const nodeHTTPS = `if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0'){console.log('CTA1 ERROR unsafe_configuration');process.exit(0)}
const https=require('https'),crypto=require('crypto');let done=false;
function emit(s){if(!done){done=true;console.log(s)}}
const req=https.get(process.argv[1],{headers:{'User-Agent':'ca-trust-audit/1'}},res=>{const c=res.socket.getPeerCertificate();if(!res.socket.authorized||!c.raw){emit('CTA1 ERROR identity_unavailable')}else{emit('CTA1 ACCEPT '+crypto.createHash('sha256').update(c.raw).digest('hex'))}res.destroy()});
req.setTimeout(10000,()=>{emit('CTA1 ERROR timeout');req.destroy()});
req.on('error',e=>{let cert=['CERT_HAS_EXPIRED','CERT_NOT_YET_VALID','UNABLE_TO_GET_ISSUER_CERT','UNABLE_TO_GET_ISSUER_CERT_LOCALLY','UNABLE_TO_VERIFY_LEAF_SIGNATURE','SELF_SIGNED_CERT_IN_CHAIN','DEPTH_ZERO_SELF_SIGNED_CERT','CERT_REVOKED','ERR_TLS_CERT_ALTNAME_INVALID'];emit(cert.includes(e.code)?'CTA1 REJECT certificate_validation':'CTA1 ERROR '+(e.code==='ENOTFOUND'?'dns':'connection_or_proxy'))});`
const phpSSL = `$u=parse_url($argv[1]);$category='connection_or_proxy';set_error_handler(function($n,$message)use(&$category){if(str_contains($message,'certificate verify failed')){$category='certificate_validation';}elseif(str_contains($message,'php_network_getaddresses')){$category='dns';}elseif(str_contains(strtolower($message),'timed out')){$category='timeout';}return true;});$ctx=stream_context_create(['ssl'=>['verify_peer'=>true,'verify_peer_name'=>true,'peer_name'=>$u['host'],'capture_peer_cert'=>true]]);$s=stream_socket_client('tls://'.$u['host'].':'.($u['port']??443),$errno,$errstr,10,STREAM_CLIENT_CONNECT,$ctx);restore_error_handler();if(!$s){echo $category==='certificate_validation'?"CTA1 REJECT certificate_validation\n":"CTA1 ERROR ".$category."\n";}else{$p=stream_context_get_params($s);$c=$p['options']['ssl']['peer_certificate']??null;echo $c?"CTA1 ACCEPT ".openssl_x509_fingerprint($c,'sha256')."\n":"CTA1 ERROR identity_unavailable\n";fclose($s);}`
const phpCurl = `$c=curl_init($argv[1]);curl_setopt_array($c,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2,CURLOPT_CERTINFO=>true,CURLOPT_TIMEOUT=>10,CURLOPT_FOLLOWLOCATION=>false,CURLOPT_WRITEFUNCTION=>function($c,$s){return strlen($s);}]);curl_exec($c);$e=curl_errno($c);if($e){echo $e===60?"CTA1 REJECT certificate_validation\n":($e===28?"CTA1 ERROR timeout\n":($e===6?"CTA1 ERROR dns\n":"CTA1 ERROR connection_or_proxy\n"));}else{$i=curl_getinfo($c,CURLINFO_CERTINFO);$pem=$i[0]['Cert']??null;echo $pem?"CTA1 ACCEPT ".openssl_x509_fingerprint($pem,'sha256')."\n":"CTA1 ERROR identity_unavailable\n";}unset($c);`
const rubyHTTPS = `require 'net/http';require 'openssl';require 'digest'
begin
 u=URI(ARGV[0]);h=Net::HTTP.new(u.host,u.port);h.use_ssl=true;h.verify_mode=OpenSSL::SSL::VERIFY_PEER;h.open_timeout=10;h.read_timeout=10
 h.start do |http|
  http.request_get(u.request_uri,{'User-Agent'=>'ca-trust-audit/1'}) do |r|
   c=http.peer_cert
   puts c ? 'CTA1 ACCEPT '+Digest::SHA256.hexdigest(c.to_der) : 'CTA1 ERROR identity_unavailable'
   break
  end
 end
rescue OpenSSL::SSL::SSLError => e
 puts e.message.include?('certificate verify failed') ? 'CTA1 REJECT certificate_validation' : 'CTA1 ERROR connection_or_proxy'
rescue Exception
 puts 'CTA1 ERROR connection_or_proxy'
end`

// EvidenceFor converts normalized results to findings. Only a pinned fixture leaf
// can establish acceptance of the incident, preventing proxy MITM false positives.
func EvidenceFor(r Result, c certificates.Chain, client string) report.Finding {
	f := report.Finding{Status: r.Status, Method: "live", Client: client, Usage: "tls", Chain: c.ID, Intermediate: c.Intermediate.Name, Root: c.Intermediate.IssuedBy, Endpoint: "https://" + c.Host + "/", Evidence: report.Evidence{Model: "runtime TLS validation", Category: r.Category, LeafSHA256: r.LeafSHA256, IntermediateSHA256: strings.ToLower(c.Intermediate.SHA256), SPKISHA256: strings.ToLower(c.Intermediate.SPKISHA256)}}
	attempted := true
	f.Evidence.Attempted = &attempted
	if r.Status == report.VulnerableClient {
		if r.RootName != "" {
			f.Root = r.RootName
			f.Evidence.RootSHA256 = r.RootSHA256
		}
		if r.VerifiedIntermediateSHA256 != "" {
			f.Evidence.IntermediateSHA256 = r.VerifiedIntermediateSHA256
		}
		if r.LeafSHA256 != certificates.SHA256(c.Certificates[0].Raw) {
			f.Status = report.Inconclusive
			f.Evidence.Category = "unexpected_peer_or_proxy"
			f.Evidence.Detail = "TLS succeeded but peer differs from the pinned published leaf; proxy interference or endpoint rotation possible"
		} else {
			f.Evidence.Detail = "client accepted the exact published compromised-chain leaf"
			f.Remediation = "Update this runtime and its CA data; apply vendor incident distrust guidance and retest."
		}
	} else {
		f.Evidence.Detail = fmt.Sprintf("%s: %s", f.Status, r.Category)
		if r.Status == report.Rejected {
			f.Evidence.Detail += "; this does not prove incident-specific distrust (expiry, hostname or other policy can reject)"
		}
	}
	return f
}
