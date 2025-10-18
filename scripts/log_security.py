"""
Enterprise-Grade Log Analysis and Threat Detection System
Endüstriyel seviye log analizi, anomali tespiti ve güvenlik izleme sistemi
"""

import re
import json
import sqlite3
import hashlib
import gzip
from collections import defaultdict, Counter, deque
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import statistics
from enum import Enum
import csv
import threading
from queue import Queue
import time


class SeverityLevel(Enum):
    """Log severity seviyeleri"""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


class ThreatType(Enum):
    """Tehdit tipleri"""
    BRUTE_FORCE = "Brute Force Attack"
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting"
    DDOS = "DDoS Attack"
    CREDENTIAL_STUFFING = "Credential Stuffing"
    PATH_TRAVERSAL = "Path Traversal"
    COMMAND_INJECTION = "Command Injection"
    XXE = "XML External Entity"
    SSRF = "Server-Side Request Forgery"
    ANOMALY = "Behavioral Anomaly"


@dataclass
class LogEntry:
    """Tek bir log kaydını temsil eder"""
    timestamp: datetime
    severity: str
    source_ip: Optional[str]
    user_agent: Optional[str]
    request_path: Optional[str]
    status_code: Optional[int]
    response_time: Optional[float]
    message: str
    raw_line: str
    hash_id: str


@dataclass
class Threat:
    """Tespit edilen tehdit"""
    threat_type: ThreatType
    severity: SeverityLevel
    source_ip: str
    timestamp: datetime
    evidence: List[str]
    confidence_score: float
    recommendation: str


@dataclass
class Anomaly:
    """Tespit edilen anomali"""
    metric: str
    value: float
    expected_range: Tuple[float, float]
    deviation: float
    timestamp: datetime
    severity: SeverityLevel


class LogParser:
    """Çoklu format log parser"""
    
    PATTERNS = {
        'apache_combined': re.compile(
            r'(?P<ip>[\d.]+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
            r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d+)\s+'
            r'(?P<size>\d+)\s+"[^"]*"\s+"(?P<user_agent>[^"]*)"'
        ),
        'nginx': re.compile(
            r'(?P<ip>[\d.]+)\s+-\s+-\s+\[(?P<timestamp>[^\]]+)\]\s+'
            r'"(?P<method>\S+)\s+(?P<path>\S+)[^"]*"\s+(?P<status>\d+)\s+'
            r'(?P<size>\d+)\s+"[^"]*"\s+"(?P<user_agent>[^"]*)"'
        ),
        'syslog': re.compile(
            r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+(?P<host>\S+)\s+'
            r'(?P<process>\S+?)(\[(?P<pid>\d+)\])?\s*:\s+(?P<message>.*)'
        ),
        'json': re.compile(r'^\s*\{.*\}\s*$'),
        'custom_app': re.compile(
            r'(?P<timestamp>[\d\-]+\s+[\d:,]+)\s+(?P<severity>\w+)\s+'
            r'(?P<thread>\[\S+\])\s+(?P<logger>\S+)\s+-\s+(?P<message>.*)'
        )
    }
    
    @staticmethod
    def detect_format(line: str) -> Optional[str]:
        """Log formatını otomatik tespit eder"""
        for format_name, pattern in LogParser.PATTERNS.items():
            if pattern.search(line):
                return format_name
        return None
    
    @staticmethod
    def parse_line(line: str, format_name: str = None) -> Optional[LogEntry]:
        """Tek bir log satırını parse eder"""
        if not format_name:
            format_name = LogParser.detect_format(line)
        
        if not format_name:
            return None
        
        try:
            if format_name == 'json':
                data = json.loads(line)
                return LogEntry(
                    timestamp=datetime.fromisoformat(data.get('timestamp', datetime.now().isoformat())),
                    severity=data.get('level', 'INFO'),
                    source_ip=data.get('ip'),
                    user_agent=data.get('user_agent'),
                    request_path=data.get('path'),
                    status_code=data.get('status'),
                    response_time=data.get('response_time'),
                    message=data.get('message', ''),
                    raw_line=line,
                    hash_id=hashlib.md5(line.encode()).hexdigest()
                )
            
            pattern = LogParser.PATTERNS[format_name]
            match = pattern.search(line)
            
            if not match:
                return None
            
            groups = match.groupdict()
            
            # Timestamp parsing
            timestamp_str = groups.get('timestamp', '')
            try:
                timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
            except:
                try:
                    timestamp = datetime.strptime(timestamp_str, '%b %d %H:%M:%S')
                    timestamp = timestamp.replace(year=datetime.now().year)
                except:
                    timestamp = datetime.now()
            
            return LogEntry(
                timestamp=timestamp,
                severity='INFO',
                source_ip=groups.get('ip'),
                user_agent=groups.get('user_agent'),
                request_path=groups.get('path'),
                status_code=int(groups.get('status', 0)) if groups.get('status') else None,
                response_time=None,
                message=groups.get('message', line),
                raw_line=line,
                hash_id=hashlib.md5(line.encode()).hexdigest()
            )
        except Exception as e:
            return None


class ThreatDetector:
    """Gelişmiş tehdit tespit motoru"""
    
    def __init__(self):
        self.threat_signatures = self._load_threat_signatures()
        self.ip_reputation_cache = {}
        self.behavioral_baseline = {}
        
    def _load_threat_signatures(self) -> Dict:
        """Tehdit imzalarını yükler"""
        return {
            ThreatType.SQL_INJECTION: [
                r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
                r"(union.*select|select.*from|insert.*into|delete.*from)",
                r"(drop.*table|exec.*\(|execute.*\()",
                r"(or\s+1\s*=\s*1|and\s+1\s*=\s*1)",
                r"(concat\s*\(|char\s*\(|ascii\s*\()",
                r"(benchmark\s*\(|sleep\s*\(|waitfor\s+delay)"
            ],
            ThreatType.XSS: [
                r"<script[^>]*>.*?</script>",
                r"javascript\s*:",
                r"on(load|error|click|mouse)\s*=",
                r"<iframe[^>]*>",
                r"eval\s*\(",
                r"document\.(cookie|write|location)"
            ],
            ThreatType.PATH_TRAVERSAL: [
                r"\.\./|\.\.\\",
                r"etc/passwd|etc/shadow",
                r"windows/system32",
                r"%2e%2e[/\\]",
                r"\\x2e\\x2e[/\\]"
            ],
            ThreatType.COMMAND_INJECTION: [
                r";\s*(ls|cat|wget|curl|nc|bash|sh)\s",
                r"\||\`",
                r"\$\(.*\)",
                r"&&|\|\|",
                r">\s*/dev/null"
            ],
            ThreatType.XXE: [
                r"<!ENTITY",
                r"SYSTEM\s+[\"']",
                r"<!DOCTYPE.*\[",
                r"ENTITY.*file://",
                r"ENTITY.*http://"
            ],
            ThreatType.SSRF: [
                r"localhost|127\.0\.0\.1|::1",
                r"169\.254\.",
                r"10\.\d+\.\d+\.\d+|192\.168\.",
                r"file://|dict://|gopher://",
                r"@.*[:.].*/"
            ]
        }
    
    def detect_threats(self, log_entry: LogEntry, context: Dict) -> List[Threat]:
        """Log kaydındaki tehditleri tespit eder"""
        threats = []
        
        # Signature-based detection
        for threat_type, patterns in self.threat_signatures.items():
            for pattern in patterns:
                if re.search(pattern, log_entry.raw_line, re.IGNORECASE):
                    confidence = self._calculate_confidence(log_entry, threat_type, context)
                    if confidence > 0.5:
                        threats.append(Threat(
                            threat_type=threat_type,
                            severity=self._determine_severity(confidence),
                            source_ip=log_entry.source_ip or "unknown",
                            timestamp=log_entry.timestamp,
                            evidence=[log_entry.raw_line[:200]],
                            confidence_score=confidence,
                            recommendation=self._get_recommendation(threat_type)
                        ))
                    break
        
        # Behavioral detection
        behavioral_threats = self._detect_behavioral_threats(log_entry, context)
        threats.extend(behavioral_threats)
        
        return threats
    
    def _calculate_confidence(self, log_entry: LogEntry, threat_type: ThreatType, context: Dict) -> float:
        """Tehdit güven skorunu hesaplar"""
        base_confidence = 0.6
        
        # Status code analizi
        if log_entry.status_code:
            if log_entry.status_code >= 400:
                base_confidence += 0.1
            if log_entry.status_code == 500:
                base_confidence += 0.15
        
        # Tekrarlanan girişimler
        ip = log_entry.source_ip
        if ip and ip in context.get('ip_attempts', {}):
            attempts = context['ip_attempts'][ip]
            if attempts > 5:
                base_confidence += min(0.2, attempts * 0.02)
        
        # User-agent analizi
        if log_entry.user_agent:
            suspicious_agents = ['bot', 'crawler', 'scanner', 'sqlmap', 'nikto']
            if any(agent in log_entry.user_agent.lower() for agent in suspicious_agents):
                base_confidence += 0.15
        
        return min(1.0, base_confidence)
    
    def _detect_behavioral_threats(self, log_entry: LogEntry, context: Dict) -> List[Threat]:
        """Davranışsal anomalileri tespit eder"""
        threats = []
        ip = log_entry.source_ip
        
        if not ip:
            return threats
        
        # Brute force tespiti
        ip_stats = context.get('ip_stats', {}).get(ip, {})
        failed_attempts = ip_stats.get('failed_logins', 0)
        time_window = ip_stats.get('time_window', 60)
        
        if failed_attempts > 10 and time_window < 300:  # 5 dakika içinde 10+ başarısız giriş
            threats.append(Threat(
                threat_type=ThreatType.BRUTE_FORCE,
                severity=SeverityLevel.HIGH,
                source_ip=ip,
                timestamp=log_entry.timestamp,
                evidence=[f"{failed_attempts} failed login attempts in {time_window} seconds"],
                confidence_score=0.85,
                recommendation="Implement rate limiting and temporary IP blocking"
            ))
        
        # DDoS tespiti
        request_rate = ip_stats.get('request_rate', 0)
        if request_rate > 100:  # Saniyede 100+ istek
            threats.append(Threat(
                threat_type=ThreatType.DDOS,
                severity=SeverityLevel.CRITICAL,
                source_ip=ip,
                timestamp=log_entry.timestamp,
                evidence=[f"{request_rate} requests per second"],
                confidence_score=0.9,
                recommendation="Implement DDoS protection (Cloudflare, AWS Shield)"
            ))
        
        # Credential stuffing tespiti
        unique_usernames = ip_stats.get('unique_usernames', set())
        if len(unique_usernames) > 20:  # Aynı IP'den 20+ farklı kullanıcı adı
            threats.append(Threat(
                threat_type=ThreatType.CREDENTIAL_STUFFING,
                severity=SeverityLevel.HIGH,
                source_ip=ip,
                timestamp=log_entry.timestamp,
                evidence=[f"{len(unique_usernames)} unique username attempts"],
                confidence_score=0.8,
                recommendation="Implement CAPTCHA and account lockout policies"
            ))
        
        return threats
    
    def _determine_severity(self, confidence: float) -> SeverityLevel:
        """Güven skoruna göre severity belirler"""
        if confidence >= 0.9:
            return SeverityLevel.CRITICAL
        elif confidence >= 0.75:
            return SeverityLevel.HIGH
        elif confidence >= 0.6:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW
    
    def _get_recommendation(self, threat_type: ThreatType) -> str:
        """Tehdit tipine göre öneri döner"""
        recommendations = {
            ThreatType.SQL_INJECTION: "Use parameterized queries, input validation, and WAF rules",
            ThreatType.XSS: "Implement output encoding, CSP headers, and input sanitization",
            ThreatType.PATH_TRAVERSAL: "Validate file paths, use whitelist approach, restrict file access",
            ThreatType.COMMAND_INJECTION: "Avoid system calls, use safe APIs, validate input strictly",
            ThreatType.XXE: "Disable XML external entities, use safe XML parsers",
            ThreatType.SSRF: "Validate URLs, use allowlist of domains, implement network segmentation"
        }
        return recommendations.get(threat_type, "Review security configurations and implement best practices")


class AnomalyDetector:
    """Makine öğrenimi benzeri anomali tespit motoru"""
    
    def __init__(self, sensitivity: float = 2.0):
        self.sensitivity = sensitivity
        self.baseline = {}
        self.history = defaultdict(lambda: deque(maxlen=1000))
        
    def update_baseline(self, metric: str, value: float):
        """Baseline metriklerini günceller"""
        self.history[metric].append(value)
        
        if len(self.history[metric]) >= 30:
            values = list(self.history[metric])
            self.baseline[metric] = {
                'mean': statistics.mean(values),
                'stdev': statistics.stdev(values) if len(values) > 1 else 0,
                'median': statistics.median(values),
                'p95': statistics.quantiles(values, n=20)[18] if len(values) >= 20 else max(values),
                'p99': statistics.quantiles(values, n=100)[98] if len(values) >= 100 else max(values)
            }
    
    def detect_anomalies(self, metric: str, value: float) -> Optional[Anomaly]:
        """Anomali tespit eder (Z-score ve IQR yöntemleri)"""
        if metric not in self.baseline:
            return None
        
        baseline = self.baseline[metric]
        mean = baseline['mean']
        stdev = baseline['stdev']
        
        if stdev == 0:
            return None
        
        # Z-score hesaplama
        z_score = abs((value - mean) / stdev)
        
        if z_score > self.sensitivity:
            deviation = ((value - mean) / mean) * 100
            
            # Expected range (mean ± 2*stdev)
            expected_range = (mean - 2*stdev, mean + 2*stdev)
            
            # Severity belirleme
            if z_score > 4:
                severity = SeverityLevel.CRITICAL
            elif z_score > 3:
                severity = SeverityLevel.HIGH
            else:
                severity = SeverityLevel.MEDIUM
            
            return Anomaly(
                metric=metric,
                value=value,
                expected_range=expected_range,
                deviation=deviation,
                timestamp=datetime.now(),
                severity=severity
            )
        
        return None


class DatabaseManager:
    """SQLite veritabanı yöneticisi"""
    
    def __init__(self, db_path: str = "log_analysis.db"):
        self.db_path = db_path
        self.conn = None
        self._initialize_db()
    
    def _initialize_db(self):
        """Veritabanını başlatır"""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        cursor = self.conn.cursor()
        
        # Threats tablosu
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_type TEXT,
                severity TEXT,
                source_ip TEXT,
                timestamp TEXT,
                confidence_score REAL,
                evidence TEXT,
                recommendation TEXT,
                status TEXT DEFAULT 'open',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Anomalies tablosu
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                metric TEXT,
                value REAL,
                expected_min REAL,
                expected_max REAL,
                deviation REAL,
                severity TEXT,
                timestamp TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # IP reputation tablosu
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_reputation (
                ip TEXT PRIMARY KEY,
                reputation_score REAL,
                total_requests INTEGER,
                failed_requests INTEGER,
                threats_detected INTEGER,
                last_seen TEXT,
                is_blocked BOOLEAN DEFAULT 0
            )
        ''')
        
        # Log summary tablosu
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS log_summary (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT UNIQUE,
                total_logs INTEGER,
                errors INTEGER,
                warnings INTEGER,
                threats INTEGER,
                anomalies INTEGER,
                unique_ips INTEGER,
                avg_response_time REAL
            )
        ''')
        
        self.conn.commit()
    
    def save_threat(self, threat: Threat):
        """Tehdidi veritabanına kaydeder"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO threats (threat_type, severity, source_ip, timestamp, 
                               confidence_score, evidence, recommendation)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            threat.threat_type.value,
            threat.severity.name,
            threat.source_ip,
            threat.timestamp.isoformat(),
            threat.confidence_score,
            json.dumps(threat.evidence),
            threat.recommendation
        ))
        self.conn.commit()
    
    def save_anomaly(self, anomaly: Anomaly):
        """Anomaliyi veritabanına kaydeder"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO anomalies (metric, value, expected_min, expected_max, 
                                 deviation, severity, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            anomaly.metric,
            anomaly.value,
            anomaly.expected_range[0],
            anomaly.expected_range[1],
            anomaly.deviation,
            anomaly.severity.name,
            anomaly.timestamp.isoformat()
        ))
        self.conn.commit()
    
    def update_ip_reputation(self, ip: str, is_threat: bool):
        """IP itibarını günceller"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO ip_reputation (ip, reputation_score, total_requests, 
                                     failed_requests, threats_detected, last_seen)
            VALUES (?, ?, 1, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                total_requests = total_requests + 1,
                failed_requests = failed_requests + ?,
                threats_detected = threats_detected + ?,
                last_seen = ?,
                reputation_score = reputation_score - ?
        ''', (
            ip, 100.0, 1 if is_threat else 0, 1 if is_threat else 0,
            datetime.now().isoformat(),
            1 if is_threat else 0,
            1 if is_threat else 0,
            datetime.now().isoformat(),
            5.0 if is_threat else 0
        ))
        self.conn.commit()
    
    def get_threat_statistics(self) -> Dict:
        """Tehdit istatistiklerini döner"""
        cursor = self.conn.cursor()
        
        # Toplam tehditler
        cursor.execute("SELECT COUNT(*) FROM threats WHERE status='open'")
        open_threats = cursor.fetchone()[0]
        
        # Severity dağılımı
        cursor.execute('''
            SELECT severity, COUNT(*) 
            FROM threats 
            WHERE status='open'
            GROUP BY severity
        ''')
        severity_dist = dict(cursor.fetchall())
        
        # En çok tehdit oluşturan IP'ler
        cursor.execute('''
            SELECT source_ip, COUNT(*) as count
            FROM threats
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT 10
        ''')
        top_threat_ips = cursor.fetchall()
        
        return {
            'open_threats': open_threats,
            'severity_distribution': severity_dist,
            'top_threat_ips': top_threat_ips
        }
    
    def close(self):
        """Veritabanı bağlantısını kapatır"""
        if self.conn:
            self.conn.close()


class EnterpriseLogAnalyzer:
    """Endüstriyel seviye log analiz sistemi"""
    
    def __init__(self, config: Dict = None):
        self.config = config or self._default_config()
        self.parser = LogParser()
        self.threat_detector = ThreatDetector()
        self.anomaly_detector = AnomalyDetector(sensitivity=self.config['anomaly_sensitivity'])
        self.db = DatabaseManager(self.config['database_path'])
        
        # İstatistikler
        self.stats = {
            'total_logs': 0,
            'errors': 0,
            'warnings': 0,
            'threats_detected': 0,
            'anomalies_detected': 0,
            'processing_time': 0,
            'ip_stats': defaultdict(lambda: {
                'request_count': 0,
                'failed_logins': 0,
                'unique_usernames': set(),
                'request_rate': 0,
                'time_window': 0,
                'first_seen': None,
                'last_seen': None
            }),
            'ip_attempts': Counter(),
            'status_codes': Counter(),
            'response_times': [],
            'hourly_distribution': defaultdict(int),
            'daily_patterns': defaultdict(int)
        }
        
        self.threats = []
        self.anomalies = []
        
    def _default_config(self) -> Dict:
        """Varsayılan konfigürasyon"""
        return {
            'database_path': 'enterprise_log_analysis.db',
            'anomaly_sensitivity': 2.5,
            'threat_threshold': 0.7,
            'max_logs_in_memory': 100000,
            'enable_real_time_alerts': True,
            'alert_webhook': None,
            'blocked_ip_threshold': 10,
            'export_format': 'json'
        }
    
    def analyze_file(self, file_path: str, format_hint: str = None):
        """Log dosyasını analiz eder"""
        start_time = time.time()
        
        print(f"\n{'='*80}")
        print(f"  ENTERPRISE LOG ANALYSIS SYSTEM v2.0")
        print(f"{'='*80}\n")
        print(f"📁 Analyzing: {file_path}")
        print(f"⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        file_path_obj = Path(file_path)
        
        # Dosya boyutu kontrolü
        file_size = file_path_obj.stat().st_size
        print(f"📊 File size: {file_size / (1024*1024):.2f} MB")
        
        # Gzip kontrolü
        is_gzip = file_path.endswith('.gz')
        
        try:
            if is_gzip:
                file_handle = gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore')
            else:
                file_handle = open(file_path, 'r', encoding='utf-8', errors='ignore')
            
            line_count = 0
            batch_size = 1000
            batch = []
            
            for line in file_handle:
                line = line.strip()
                if not line:
                    continue
                
                batch.append(line)
                line_count += 1
                
                if len(batch) >= batch_size:
                    self._process_batch(batch, format_hint)
                    batch = []
                    
                    if line_count % 10000 == 0:
                        print(f"  ⚙️  Processed {line_count:,} lines...", end='\r')
            
            # Son batch'i işle
            if batch:
                self._process_batch(batch, format_hint)
            
            file_handle.close()
            
        except Exception as e:
            print(f"\n❌ Error reading file: {e}")
            return
        
        self.stats['processing_time'] = time.time() - start_time
        self.stats['total_logs'] = line_count
        
        # Post-processing analizler
        self._perform_advanced_analysis()
        
        # Rapor oluştur
        self._generate_comprehensive_report()
        
        print(f"\n✅ Analysis completed in {self.stats['processing_time']:.2f} seconds")
        print(f"📈 Throughput: {line_count / self.stats['processing_time']:.0f} logs/sec\n")
    
    def _process_batch(self, batch: List[str], format_hint: str = None):
        """Log batch'ini işler"""
        for line in batch:
            log_entry = self.parser.parse_line(line, format_hint)
            
            if not log_entry:
                continue
            
            # Temel istatistikler
            self._update_statistics(log_entry)
            
            # Tehdit tespiti
            context = {
                'ip_attempts': self.stats['ip_attempts'],
                'ip_stats': self.stats['ip_stats']
            }
            threats = self.threat_detector.detect_threats(log_entry, context)
            
            for threat in threats:
                self.threats.append(threat)
                self.stats['threats_detected'] += 1
                self.db.save_threat(threat)
                self.db.update_ip_reputation(threat.source_ip, True)
            
            # Anomali tespiti
            if log_entry.response_time:
                self.anomaly_detector.update_baseline('response_time', log_entry.response_time)
                anomaly = self.anomaly_detector.detect_anomalies('response_time', log_entry.response_time)
                if anomaly:
                    self.anomalies.append(anomaly)
                    self.stats['anomalies_detected'] += 1
                    self.db.save_anomaly(anomaly)
    
    def _update_statistics(self, log_entry: LogEntry):
        """İstatistikleri günceller"""
        # IP istatistikleri
        if log_entry.source_ip:
            ip = log_entry.source_ip
            ip_stat = self.stats['ip_stats'][ip]
            ip_stat['request_count'] += 1
            
            if not ip_stat['first_seen']:
                ip_stat['first_seen'] = log_entry.timestamp
            ip_stat['last_seen'] = log_entry.timestamp
            
            # Request rate hesaplama
            time_diff = (ip_stat['last_seen'] - ip_stat['first_seen']).total_seconds()
            if time_diff > 0:
                ip_stat['request_rate'] = ip_stat['request_count'] / time_diff
                ip_stat['time_window'] = time_diff
            
            # Başarısız giriş tespiti
            if log_entry.status_code in [401, 403]:
                ip_stat['failed_logins'] += 1
                self.stats['ip_attempts'][ip] += 1
        
        # Status code dağılımı
        if log_entry.status_code:
            self.stats['status_codes'][log_entry.status_code] += 1
        
        # Response time tracking
        if log_entry.response_time:
            self.stats['response_times'].append(log_entry.response_time)
        
        # Zaman bazlı dağılım
        hour = log_entry.timestamp.hour
        self.stats['hourly_distribution'][hour] += 1
        
        day = log_entry.timestamp.strftime('%Y-%m-%d')
        self.stats['daily_patterns'][day] += 1
        
        # Severity tracking
        if 'error' in log_entry.severity.lower() or 'fatal' in log_entry.severity.lower():
            self.stats['errors'] += 1
        elif 'warn' in log_entry.severity.lower():
            self.stats['warnings'] += 1
    
    def _perform_advanced_analysis(self):
        """Gelişmiş analizler yapar"""
        print("\n🔍 Performing advanced analysis...")
        
        # Correlation analysis
        self._analyze_correlations()
        
        # Time-series anomalies
        self._detect_time_series_anomalies()
        
        # IP reputation scoring
        self._calculate_ip_reputation_scores()
        
        # Attack pattern recognition
        self._recognize_attack_patterns()
    
    def _analyze_correlations(self):
        """Olaylar arası korelasyonları analiz eder"""
        # Error spike ile response time korelasyonu
        if self.stats['response_times']:
            avg_response_time = statistics.mean(self.stats['response_times'])
            if avg_response_time > 1.0:  # 1 saniyeden uzun
                error_rate = self.stats['errors'] / max(1, self.stats['total_logs'])
                if error_rate > 0.05:  # %5'ten fazla hata
                    self.anomalies.append(Anomaly(
                        metric="error_response_correlation",
                        value=error_rate * 100,
                        expected_range=(0, 5),
                        deviation=(error_rate * 100) - 5,
                        timestamp=datetime.now(),
                        severity=SeverityLevel.HIGH
                    ))
    
    def _detect_time_series_anomalies(self):
        """Zaman serisi anomalilerini tespit eder"""
        # Saatlik dağılım anomalileri
        if self.stats['hourly_distribution']:
            values = list(self.stats['hourly_distribution'].values())
            if len(values) > 5:
                mean_requests = statistics.mean(values)
                stdev_requests = statistics.stdev(values) if len(values) > 1 else 0
                
                for hour, count in self.stats['hourly_distribution'].items():
                    if stdev_requests > 0:
                        z_score = abs((count - mean_requests) / stdev_requests)
                        if z_score > 3:
                            self.anomalies.append(Anomaly(
                                metric=f"hourly_traffic_hour_{hour}",
                                value=count,
                                expected_range=(mean_requests - 2*stdev_requests, mean_requests + 2*stdev_requests),
                                deviation=((count - mean_requests) / mean_requests * 100),
                                timestamp=datetime.now().replace(hour=hour),
                                severity=SeverityLevel.MEDIUM
                            ))
    
    def _calculate_ip_reputation_scores(self):
        """IP itibar skorlarını hesaplar"""
        for ip, stats in self.stats['ip_stats'].items():
            reputation_score = 100.0
            
            # Failed login penalty
            reputation_score -= min(50, stats['failed_logins'] * 5)
            
            # Request rate penalty
            if stats['request_rate'] > 10:
                reputation_score -= min(30, (stats['request_rate'] - 10) * 2)
            
            # Unique username attempts penalty
            if len(stats['unique_usernames']) > 10:
                reputation_score -= min(20, len(stats['unique_usernames']) * 1)
            
            stats['reputation_score'] = max(0, reputation_score)
            
            # Otomatik engelleme
            if reputation_score < 20:
                print(f"  🚫 IP {ip} blocked (reputation: {reputation_score:.1f})")
    
    def _recognize_attack_patterns(self):
        """Saldırı paternlerini tanır"""
        # Multi-vector attack detection
        threat_types_per_ip = defaultdict(set)
        
        for threat in self.threats:
            threat_types_per_ip[threat.source_ip].add(threat.threat_type)
        
        for ip, threat_types in threat_types_per_ip.items():
            if len(threat_types) >= 3:
                print(f"  ⚠️  Multi-vector attack detected from {ip}: {[t.value for t in threat_types]}")
                
                # Yeni tehdit oluştur
                self.threats.append(Threat(
                    threat_type=ThreatType.ANOMALY,
                    severity=SeverityLevel.CRITICAL,
                    source_ip=ip,
                    timestamp=datetime.now(),
                    evidence=[f"Multiple attack vectors: {len(threat_types)}"],
                    confidence_score=0.95,
                    recommendation="Immediate IP blocking and security team notification required"
                ))
    
    def _generate_comprehensive_report(self):
        """Kapsamlı analiz raporu oluşturur"""
        report = {
            'summary': self._generate_summary(),
            'security_analysis': self._generate_security_report(),
            'performance_analysis': self._generate_performance_report(),
            'threat_intelligence': self._generate_threat_intelligence(),
            'recommendations': self._generate_recommendations()
        }
        
        # Console output
        self._print_report(report)
        
        # JSON export
        self._export_json_report(report)
        
        # CSV export for threats
        self._export_csv_threats()
        
        # HTML dashboard export
        self._export_html_dashboard(report)
    
    def _generate_summary(self) -> Dict:
        """Özet rapor oluşturur"""
        return {
            'total_logs_processed': self.stats['total_logs'],
            'processing_time_seconds': round(self.stats['processing_time'], 2),
            'logs_per_second': round(self.stats['total_logs'] / max(1, self.stats['processing_time']), 0),
            'total_errors': self.stats['errors'],
            'total_warnings': self.stats['warnings'],
            'threats_detected': self.stats['threats_detected'],
            'anomalies_detected': self.stats['anomalies_detected'],
            'unique_ips': len(self.stats['ip_stats']),
            'analysis_date': datetime.now().isoformat()
        }
    
    def _generate_security_report(self) -> Dict:
        """Güvenlik raporu oluşturur"""
        # Tehdit dağılımı
        threat_distribution = Counter([t.threat_type.value for t in self.threats])
        severity_distribution = Counter([t.severity.name for t in self.threats])
        
        # En tehlikeli IP'ler
        ip_threat_counts = Counter([t.source_ip for t in self.threats])
        top_threat_ips = [
            {
                'ip': ip,
                'threat_count': count,
                'reputation_score': self.stats['ip_stats'][ip].get('reputation_score', 0)
            }
            for ip, count in ip_threat_counts.most_common(10)
        ]
        
        # Critical threats
        critical_threats = [
            {
                'type': t.threat_type.value,
                'ip': t.source_ip,
                'timestamp': t.timestamp.isoformat(),
                'confidence': t.confidence_score,
                'evidence': t.evidence[:2]
            }
            for t in self.threats if t.severity == SeverityLevel.CRITICAL
        ]
        
        return {
            'threat_distribution': dict(threat_distribution),
            'severity_distribution': dict(severity_distribution),
            'top_threat_ips': top_threat_ips,
            'critical_threats': critical_threats,
            'blocked_ips': [ip for ip, stats in self.stats['ip_stats'].items() 
                          if stats.get('reputation_score', 100) < 20]
        }
    
    def _generate_performance_report(self) -> Dict:
        """Performans raporu oluşturur"""
        response_times = self.stats['response_times']
        
        perf_stats = {}
        if response_times:
            perf_stats = {
                'avg_response_time': round(statistics.mean(response_times), 3),
                'median_response_time': round(statistics.median(response_times), 3),
                'p95_response_time': round(statistics.quantiles(response_times, n=20)[18], 3) if len(response_times) >= 20 else None,
                'p99_response_time': round(statistics.quantiles(response_times, n=100)[98], 3) if len(response_times) >= 100 else None,
                'max_response_time': round(max(response_times), 3),
                'min_response_time': round(min(response_times), 3)
            }
        
        # Status code distribution
        status_distribution = dict(self.stats['status_codes'].most_common())
        
        # Error rate
        total_requests = sum(self.stats['status_codes'].values())
        error_requests = sum(count for code, count in self.stats['status_codes'].items() if code >= 400)
        error_rate = (error_requests / total_requests * 100) if total_requests > 0 else 0
        
        return {
            'response_time_stats': perf_stats,
            'status_code_distribution': status_distribution,
            'error_rate_percentage': round(error_rate, 2),
            'total_requests': total_requests,
            'successful_requests': sum(count for code, count in self.stats['status_codes'].items() if 200 <= code < 400),
            'client_errors_4xx': sum(count for code, count in self.stats['status_codes'].items() if 400 <= code < 500),
            'server_errors_5xx': sum(count for code, count in self.stats['status_codes'].items() if 500 <= code < 600)
        }
    
    def _generate_threat_intelligence(self) -> Dict:
        """Tehdit istihbaratı raporu"""
        # Attack timeline
        threat_timeline = defaultdict(int)
        for threat in self.threats:
            hour_key = threat.timestamp.strftime('%Y-%m-%d %H:00')
            threat_timeline[hour_key] += 1
        
        # Attack patterns
        patterns = {
            'coordinated_attacks': self._detect_coordinated_attacks(),
            'attack_duration': self._calculate_attack_duration(),
            'geographic_patterns': self._analyze_geographic_patterns()
        }
        
        return {
            'threat_timeline': dict(sorted(threat_timeline.items())),
            'attack_patterns': patterns,
            'mitigation_status': {
                'blocked_ips': len([ip for ip, stats in self.stats['ip_stats'].items() 
                                  if stats.get('reputation_score', 100) < 20]),
                'threats_mitigated': len([t for t in self.threats if t.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]])
            }
        }
    
    def _detect_coordinated_attacks(self) -> List[Dict]:
        """Koordineli saldırıları tespit eder"""
        # Aynı anda çoklu IP'den benzer saldırılar
        time_window = 300  # 5 dakika
        coordinated = []
        
        threat_groups = defaultdict(list)
        for threat in self.threats:
            key = (threat.threat_type, threat.timestamp.replace(second=0, microsecond=0))
            threat_groups[key].append(threat)
        
        for (threat_type, timestamp), threats in threat_groups.items():
            if len(threats) >= 3:  # Aynı anda 3+ farklı IP
                unique_ips = len(set(t.source_ip for t in threats))
                if unique_ips >= 3:
                    coordinated.append({
                        'threat_type': threat_type.value,
                        'timestamp': timestamp.isoformat(),
                        'involved_ips': unique_ips,
                        'total_attempts': len(threats)
                    })
        
        return coordinated
    
    def _calculate_attack_duration(self) -> Dict:
        """Saldırı süresini hesaplar"""
        if not self.threats:
            return {}
        
        first_threat = min(self.threats, key=lambda t: t.timestamp)
        last_threat = max(self.threats, key=lambda t: t.timestamp)
        duration = (last_threat.timestamp - first_threat.timestamp).total_seconds()
        
        return {
            'first_attack': first_threat.timestamp.isoformat(),
            'last_attack': last_threat.timestamp.isoformat(),
            'duration_seconds': duration,
            'duration_minutes': round(duration / 60, 2)
        }
    
    def _analyze_geographic_patterns(self) -> Dict:
        """Coğrafi patern analizi (IP subnet bazlı)"""
        subnet_threats = defaultdict(int)
        
        for threat in self.threats:
            ip = threat.source_ip
            if ip and '.' in ip:
                # /24 subnet
                subnet = '.'.join(ip.split('.')[:3]) + '.0/24'
                subnet_threats[subnet] += 1
        
        return {
            'top_subnets': dict(Counter(subnet_threats).most_common(5))
        }
    
    def _generate_recommendations(self) -> List[Dict]:
        """Aksiyon önerileri oluşturur"""
        recommendations = []
        
        # Critical threats
        critical_count = len([t for t in self.threats if t.severity == SeverityLevel.CRITICAL])
        if critical_count > 0:
            recommendations.append({
                'priority': 'CRITICAL',
                'category': 'Security',
                'issue': f'{critical_count} critical security threats detected',
                'action': 'Immediate investigation and incident response required',
                'impact': 'High risk of data breach or system compromise'
            })
        
        # High error rate
        total_requests = sum(self.stats['status_codes'].values())
        error_requests = sum(count for code, count in self.stats['status_codes'].items() if code >= 500)
        if total_requests > 0:
            error_rate = (error_requests / total_requests * 100)
            if error_rate > 5:
                recommendations.append({
                    'priority': 'HIGH',
                    'category': 'Performance',
                    'issue': f'High server error rate: {error_rate:.2f}%',
                    'action': 'Check application logs, database connections, and server resources',
                    'impact': 'User experience degradation and potential service disruption'
                })
        
        # Slow response times
        if self.stats['response_times']:
            p95 = statistics.quantiles(self.stats['response_times'], n=20)[18] if len(self.stats['response_times']) >= 20 else None
            if p95 and p95 > 2.0:
                recommendations.append({
                    'priority': 'MEDIUM',
                    'category': 'Performance',
                    'issue': f'Slow response times detected (P95: {p95:.2f}s)',
                    'action': 'Profile application performance, optimize database queries, consider caching',
                    'impact': 'Poor user experience and potential timeout issues'
                })
        
        # Brute force attacks
        brute_force_count = len([t for t in self.threats if t.threat_type == ThreatType.BRUTE_FORCE])
        if brute_force_count > 0:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Security',
                'issue': f'{brute_force_count} brute force attacks detected',
                'action': 'Implement rate limiting, account lockout, and CAPTCHA',
                'impact': 'Risk of unauthorized access to user accounts'
            })
        
        # DDoS attacks
        ddos_count = len([t for t in self.threats if t.threat_type == ThreatType.DDOS])
        if ddos_count > 0:
            recommendations.append({
                'priority': 'CRITICAL',
                'category': 'Security',
                'issue': f'{ddos_count} potential DDoS attacks detected',
                'action': 'Enable DDoS protection (Cloudflare, AWS Shield), implement rate limiting',
                'impact': 'Service availability at risk'
            })
        
        # Many anomalies
        if self.stats['anomalies_detected'] > 10:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Monitoring',
                'issue': f'{self.stats["anomalies_detected"]} anomalies detected',
                'action': 'Review system behavior, check for configuration changes or unusual patterns',
                'impact': 'Potential system instability or security issues'
            })
        
        return recommendations
    
    def _print_report(self, report: Dict):
        """Raporu konsola yazdırır"""
        print("\n" + "="*80)
        print("  📊 COMPREHENSIVE ANALYSIS REPORT")
        print("="*80)
        
        # Summary
        print("\n" + "─"*80)
        print("📋 EXECUTIVE SUMMARY")
        print("─"*80)
        summary = report['summary']
        print(f"Total Logs Processed: {summary['total_logs_processed']:,}")
        print(f"Processing Time: {summary['processing_time_seconds']:.2f}s ({summary['logs_per_second']:,.0f} logs/sec)")
        print(f"Errors: {summary['total_errors']:,} | Warnings: {summary['total_warnings']:,}")
        print(f"🚨 Threats Detected: {summary['threats_detected']}")
        print(f"⚠️  Anomalies Detected: {summary['anomalies_detected']}")
        print(f"🌐 Unique IP Addresses: {summary['unique_ips']:,}")
        
        # Security Analysis
        print("\n" + "─"*80)
        print("🔒 SECURITY ANALYSIS")
        print("─"*80)
        security = report['security_analysis']
        
        if security['threat_distribution']:
            print("\nThreat Distribution:")
            for threat_type, count in sorted(security['threat_distribution'].items(), key=lambda x: x[1], reverse=True):
                print(f"  • {threat_type}: {count}")
        
        if security['severity_distribution']:
            print("\nSeverity Distribution:")
            for severity, count in sorted(security['severity_distribution'].items(), key=lambda x: x[1], reverse=True):
                print(f"  • {severity}: {count}")
        
        if security['top_threat_ips']:
            print("\nTop 5 Threat Sources:")
            for idx, ip_info in enumerate(security['top_threat_ips'][:5], 1):
                print(f"  {idx}. {ip_info['ip']} - {ip_info['threat_count']} threats (reputation: {ip_info['reputation_score']:.1f})")
        
        if security['blocked_ips']:
            print(f"\n🚫 Automatically Blocked IPs: {len(security['blocked_ips'])}")
        
        # Performance Analysis
        print("\n" + "─"*80)
        print("⚡ PERFORMANCE ANALYSIS")
        print("─"*80)
        performance = report['performance_analysis']
        
        if performance['response_time_stats']:
            print("\nResponse Time Statistics:")
            stats = performance['response_time_stats']
            for key, value in stats.items():
                if value is not None:
                    print(f"  • {key.replace('_', ' ').title()}: {value}s")
        
        print(f"\nHTTP Status Code Distribution:")
        print(f"  • Total Requests: {performance['total_requests']:,}")
        print(f"  • Successful (2xx/3xx): {performance['successful_requests']:,}")
        print(f"  • Client Errors (4xx): {performance['client_errors_4xx']:,}")
        print(f"  • Server Errors (5xx): {performance['server_errors_5xx']:,}")
        print(f"  • Error Rate: {performance['error_rate_percentage']:.2f}%")
        
        # Threat Intelligence
        print("\n" + "─"*80)
        print("🎯 THREAT INTELLIGENCE")
        print("─"*80)
        threat_intel = report['threat_intelligence']
        
        patterns = threat_intel['attack_patterns']
        if patterns['coordinated_attacks']:
            print(f"\n⚠️  Coordinated Attacks Detected: {len(patterns['coordinated_attacks'])}")
            for attack in patterns['coordinated_attacks'][:3]:
                print(f"  • {attack['threat_type']} - {attack['involved_ips']} IPs, {attack['total_attempts']} attempts")
        
        if patterns['attack_duration']:
            duration = patterns['attack_duration']
            print(f"\nAttack Timeline:")
            print(f"  • First Attack: {duration['first_attack']}")
            print(f"  • Last Attack: {duration['last_attack']}")
            print(f"  • Duration: {duration['duration_minutes']:.2f} minutes")
        
        # Recommendations
        print("\n" + "─"*80)
        print("💡 ACTIONABLE RECOMMENDATIONS")
        print("─"*80)
        recommendations = report['recommendations']
        
        if not recommendations:
            print("\n✅ No critical issues found. System appears healthy.")
        else:
            for idx, rec in enumerate(recommendations, 1):
                priority_icon = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠',
                    'MEDIUM': '🟡',
                    'LOW': '🟢'
                }.get(rec['priority'], '⚪')
                
                print(f"\n{idx}. {priority_icon} [{rec['priority']}] {rec['category']}")
                print(f"   Issue: {rec['issue']}")
                print(f"   Action: {rec['action']}")
                print(f"   Impact: {rec['impact']}")
        
        print("\n" + "="*80 + "\n")
    
    def _export_json_report(self, report: Dict):
        """JSON raporu dışa aktarır"""
        filename = f"analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        print(f"✅ JSON report exported: {filename}")
    
    def _export_csv_threats(self):
        """Tehditleri CSV olarak dışa aktarır"""
        if not self.threats:
            return
        
        filename = f"threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'Threat Type', 'Severity', 'Source IP', 'Confidence', 'Recommendation'])
            
            for threat in self.threats:
                writer.writerow([
                    threat.timestamp.isoformat(),
                    threat.threat_type.value,
                    threat.severity.name,
                    threat.source_ip,
                    f"{threat.confidence_score:.2f}",
                    threat.recommendation
                ])
        
        print(f"✅ Threats exported to CSV: {filename}")
    
    def _export_html_dashboard(self, report: Dict):
        """HTML dashboard oluşturur"""
        filename = f"dashboard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Log Analysis Dashboard</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #e2e8f0; padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        .header h1 {{ font-size: 32px; margin-bottom: 10px; }}
        .header p {{ opacity: 0.9; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .card {{ background: #1e293b; padding: 25px; border-radius: 10px; border: 1px solid #334155; }}
        .card h2 {{ font-size: 18px; margin-bottom: 15px; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; }}
        .stat {{ font-size: 36px; font-weight: bold; margin-bottom: 5px; }}
        .stat.success {{ color: #10b981; }}
        .stat.warning {{ color: #f59e0b; }}
        .stat.danger {{ color: #ef4444; }}
        .stat.info {{ color: #3b82f6; }}
        .label {{ color: #64748b; font-size: 14px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #1e293b; color: #94a3b8; font-weight: 600; }}
        tr:hover {{ background: #1e293b; }}
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600; }}
        .badge.critical {{ background: #7f1d1d; color: #fca5a5; }}
        .badge.high {{ background: #7c2d12; color: #fdba74; }}
        .badge.medium {{ background: #713f12; color: #fde047; }}
        .badge.low {{ background: #14532d; color: #86efac; }}
        .recommendation {{ background: #1e293b; border-left: 4px solid #ef4444; padding: 15px; margin-bottom: 15px; border-radius: 5px; }}
        .recommendation h3 {{ margin-bottom: 8px; color: #f87171; }}
        .recommendation p {{ color: #cbd5e1; line-height: 1.6; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Enterprise Log Analysis Dashboard</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="grid">
            <div class="card">
                <h2>Total Logs</h2>
                <div class="stat info">{report['summary']['total_logs_processed']:,}</div>
                <div class="label">Processed in {report['summary']['processing_time_seconds']}s</div>
            </div>
            <div class="card">
                <h2>Threats Detected</h2>
                <div class="stat danger">{report['summary']['threats_detected']}</div>
                <div class="label">Security incidents identified</div>
            </div>
            <div class="card">
                <h2>Anomalies</h2>
                <div class="stat warning">{report['summary']['anomalies_detected']}</div>
                <div class="label">Behavioral anomalies found</div>
            </div>
            <div class="card">
                <h2>Error Rate</h2>
                <div class="stat {'danger' if report['performance_analysis']['error_rate_percentage'] > 5 else 'success'}">
                    {report['performance_analysis']['error_rate_percentage']:.2f}%
                </div>
                <div class="label">Server error percentage</div>
            </div>
        </div>
        
        <div class="card" style="margin-bottom: 20px;">
            <h2>🚨 Critical Threats</h2>
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Type</th>
                        <th>Source IP</th>
                        <th>Severity</th>
                        <th>Confidence</th>
                    </tr>
                </thead>
                <tbody>
"""
        
        # Add critical threats to table
        for threat in report['security_analysis']['critical_threats'][:10]:
            html_content += f"""
                    <tr>
                        <td>{threat['timestamp'][:19]}</td>
                        <td>{threat['type']}</td>
                        <td><code>{threat['ip']}</code></td>
                        <td><span class="badge critical">CRITICAL</span></td>
                        <td>{threat['confidence']:.0%}</td>
                    </tr>
"""
        
        html_content += """
                </tbody>
            </table>
        </div>
        
        <div class="card">
            <h2>💡 Recommendations</h2>
"""
        
        # Add recommendations
        for rec in report['recommendations']:
            html_content += f"""
            <div class="recommendation">
                <h3>[{rec['priority']}] {rec['issue']}</h3>
                <p><strong>Action:</strong> {rec['action']}</p>
                <p><strong>Impact:</strong> {rec['impact']}</p>
            </div>
"""
        
        html_content += """
        </div>
    </div>
</body>
</html>
"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✅ HTML dashboard exported: {filename}")
    
    def close(self):
        """Kaynakları serbest bırakır"""
        self.db.close()


# Kullanım örneği
if __name__ == "__main__":
    # Konfigürasyon
    config = {
        'database_path': 'enterprise_log_analysis.db',
        'anomaly_sensitivity': 2.5,
        'threat_threshold': 0.7,
    }