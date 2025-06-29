"""
Memory Manager - Tracks previous model outputs to avoid duplication and false positives
"""

import json
import logging
import sqlite3
import hashlib
from typing import Dict, Any, List, Optional, Set
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger(__name__)


class FindingType(Enum):
    VULNERABILITY = "vulnerability"
    FALSE_POSITIVE = "false_positive"
    INFORMATION = "information"
    EXPLOITATION = "exploitation"


@dataclass
class Finding:
    id: str
    type: FindingType
    title: str
    description: str
    url: str
    method: str
    parameters: Dict[str, Any]
    evidence: Dict[str, Any]
    severity: str
    confidence: float
    created_at: datetime
    updated_at: datetime
    tags: List[str]
    model_used: str
    hash: str


@dataclass
class FeedbackEntry:
    finding_id: str
    feedback_type: str  # "confirmed", "false_positive", "duplicate", "improvement"
    feedback_data: Dict[str, Any]
    created_at: datetime
    source: str  # "human", "automated", "cross_validation"


class MemoryManager:
    """Manages triage feedback memory and prevents duplicate vulnerability reports"""
    
    def __init__(self, db_path: str = "data/memory.db", config: Optional[Dict] = None):
        self.db_path = Path(db_path)
        self.config = config or {}
        self.retention_days = self.config.get('retention_days', 90)
        self.similarity_threshold = self.config.get('similarity_threshold', 0.85)
        
        # Ensure directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        self._init_database()
        
        # In-memory caches for performance
        self._findings_cache: Dict[str, Finding] = {}
        self._hash_index: Dict[str, str] = {}  # hash -> finding_id
        self._url_index: Dict[str, Set[str]] = {}  # url -> set of finding_ids
        
        # Load recent findings into cache
        self._load_cache()
    
    def _init_database(self):
        """Initialize SQLite database with required tables"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS findings (
                        id TEXT PRIMARY KEY,
                        type TEXT NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT,
                        url TEXT NOT NULL,
                        method TEXT NOT NULL,
                        parameters TEXT,
                        evidence TEXT,
                        severity TEXT,
                        confidence REAL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        tags TEXT,
                        model_used TEXT,
                        hash TEXT UNIQUE NOT NULL
                    );
                    
                    CREATE TABLE IF NOT EXISTS feedback (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        finding_id TEXT NOT NULL,
                        feedback_type TEXT NOT NULL,
                        feedback_data TEXT,
                        created_at TEXT NOT NULL,
                        source TEXT NOT NULL,
                        FOREIGN KEY (finding_id) REFERENCES findings (id)
                    );
                    
                    CREATE INDEX IF NOT EXISTS idx_findings_hash ON findings(hash);
                    CREATE INDEX IF NOT EXISTS idx_findings_url ON findings(url);
                    CREATE INDEX IF NOT EXISTS idx_findings_created ON findings(created_at);
                    CREATE INDEX IF NOT EXISTS idx_feedback_finding ON feedback(finding_id);
                """)
                logger.info("Database initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise
    
    def _load_cache(self):
        """Load recent findings into memory cache"""
        try:
            cutoff_date = datetime.now() - timedelta(days=7)  # Cache last 7 days
            
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute("""
                    SELECT * FROM findings 
                    WHERE created_at > ? 
                    ORDER BY created_at DESC
                """, (cutoff_date.isoformat(),))
                
                for row in cursor:
                    finding = self._row_to_finding(row)
                    self._findings_cache[finding.id] = finding
                    self._hash_index[finding.hash] = finding.id
                    
                    # Update URL index
                    if finding.url not in self._url_index:
                        self._url_index[finding.url] = set()
                    self._url_index[finding.url].add(finding.id)
                
                logger.info(f"Loaded {len(self._findings_cache)} findings into cache")
                
        except Exception as e:
            logger.error(f"Failed to load cache: {e}")
    
    def _row_to_finding(self, row: sqlite3.Row) -> Finding:
        """Convert database row to Finding object"""
        return Finding(
            id=row['id'],
            type=FindingType(row['type']),
            title=row['title'],
            description=row['description'],
            url=row['url'],
            method=row['method'],
            parameters=json.loads(row['parameters']) if row['parameters'] else {},
            evidence=json.loads(row['evidence']) if row['evidence'] else {},
            severity=row['severity'],
            confidence=row['confidence'],
            created_at=datetime.fromisoformat(row['created_at']),
            updated_at=datetime.fromisoformat(row['updated_at']),
            tags=json.loads(row['tags']) if row['tags'] else [],
            model_used=row['model_used'],
            hash=row['hash']
        )
    
    def _calculate_finding_hash(self, 
                               url: str, 
                               method: str, 
                               vulnerability_type: str, 
                               parameters: Dict[str, Any]) -> str:
        """Calculate unique hash for a finding"""
        # Create a normalized string for hashing
        hash_data = {
            'url': url.lower().strip(),
            'method': method.upper().strip(),
            'type': vulnerability_type.lower().strip(),
            'params': sorted(parameters.items()) if parameters else []
        }
        
        hash_string = json.dumps(hash_data, sort_keys=True)
        return hashlib.sha256(hash_string.encode()).hexdigest()
    
    def store_finding(self, 
                     vulnerability_type: str,
                     title: str,
                     description: str,
                     url: str,
                     method: str,
                     parameters: Dict[str, Any] = None,
                     evidence: Dict[str, Any] = None,
                     severity: str = "medium",
                     confidence: float = 0.5,
                     tags: List[str] = None,
                     model_used: str = "unknown") -> Optional[Finding]:
        """Store a new finding or return existing duplicate"""
        
        parameters = parameters or {}
        evidence = evidence or {}
        tags = tags or []
        
        # Calculate hash
        finding_hash = self._calculate_finding_hash(url, method, vulnerability_type, parameters)
        
        # Check for duplicates
        existing_finding = self.find_duplicate(finding_hash)
        if existing_finding:
            logger.info(f"Duplicate finding detected: {existing_finding.id}")
            return existing_finding
        
        # Create new finding
        finding_id = f"finding_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{finding_hash[:8]}"
        now = datetime.now()
        
        finding = Finding(
            id=finding_id,
            type=FindingType.VULNERABILITY,
            title=title,
            description=description,
            url=url,
            method=method,
            parameters=parameters,
            evidence=evidence,
            severity=severity,
            confidence=confidence,
            created_at=now,
            updated_at=now,
            tags=tags,
            model_used=model_used,
            hash=finding_hash
        )
        
        try:
            # Store in database
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO findings (
                        id, type, title, description, url, method, parameters, 
                        evidence, severity, confidence, created_at, updated_at, 
                        tags, model_used, hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    finding.id, finding.type.value, finding.title, finding.description,
                    finding.url, finding.method, json.dumps(finding.parameters),
                    json.dumps(finding.evidence), finding.severity, finding.confidence,
                    finding.created_at.isoformat(), finding.updated_at.isoformat(),
                    json.dumps(finding.tags), finding.model_used, finding.hash
                ))
            
            # Update cache
            self._findings_cache[finding.id] = finding
            self._hash_index[finding.hash] = finding.id
            
            if finding.url not in self._url_index:
                self._url_index[finding.url] = set()
            self._url_index[finding.url].add(finding.id)
            
            logger.info(f"Stored new finding: {finding.id}")
            return finding
            
        except sqlite3.IntegrityError:
            # Hash collision - finding already exists
            logger.warning(f"Hash collision detected for finding: {finding_hash}")
            return self.find_duplicate(finding_hash)
        except Exception as e:
            logger.error(f"Failed to store finding: {e}")
            return None
    
    def find_duplicate(self, finding_hash: str) -> Optional[Finding]:
        """Find duplicate finding by hash"""
        # Check cache first
        if finding_hash in self._hash_index:
            finding_id = self._hash_index[finding_hash]
            return self._findings_cache.get(finding_id)
        
        # Check database
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute("SELECT * FROM findings WHERE hash = ?", (finding_hash,))
                row = cursor.fetchone()
                
                if row:
                    return self._row_to_finding(row)
                    
        except Exception as e:
            logger.error(f"Failed to find duplicate: {e}")
        
        return None
    
    def find_similar_findings(self, url: str, vulnerability_type: str, threshold: float = None) -> List[Finding]:
        """Find similar findings for the same URL and vulnerability type"""
        threshold = threshold or self.similarity_threshold
        similar_findings = []
        
        # Get all findings for the same URL
        url_findings = self._url_index.get(url, set())
        
        for finding_id in url_findings:
            finding = self._findings_cache.get(finding_id)
            if not finding:
                continue
            
            # Check if vulnerability types are similar
            if self._calculate_similarity(vulnerability_type.lower(), finding.title.lower()) >= threshold:
                similar_findings.append(finding)
        
        return similar_findings
    
    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity between two text strings"""
        # Simple word-based similarity
        words1 = set(text1.split())
        words2 = set(text2.split())
        
        if not words1 and not words2:
            return 1.0
        if not words1 or not words2:
            return 0.0
        
        intersection = words1.intersection(words2)
        union = words1.union(words2)
        
        return len(intersection) / len(union)
    
    def add_feedback(self, 
                    finding_id: str, 
                    feedback_type: str, 
                    feedback_data: Dict[str, Any] = None,
                    source: str = "human") -> bool:
        """Add feedback for a finding"""
        
        feedback_data = feedback_data or {}
        
        try:
            feedback_entry = FeedbackEntry(
                finding_id=finding_id,
                feedback_type=feedback_type,
                feedback_data=feedback_data,
                created_at=datetime.now(),
                source=source
            )
            
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO feedback (finding_id, feedback_type, feedback_data, created_at, source)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    feedback_entry.finding_id,
                    feedback_entry.feedback_type,
                    json.dumps(feedback_entry.feedback_data),
                    feedback_entry.created_at.isoformat(),
                    feedback_entry.source
                ))
            
            # Update finding status if needed
            if feedback_type == "false_positive":
                self._mark_false_positive(finding_id)
            elif feedback_type == "confirmed":
                self._mark_confirmed(finding_id)
            
            logger.info(f"Added feedback for finding {finding_id}: {feedback_type}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add feedback: {e}")
            return False
    
    def _mark_false_positive(self, finding_id: str):
        """Mark a finding as false positive"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    UPDATE findings 
                    SET type = ?, updated_at = ?
                    WHERE id = ?
                """, (FindingType.FALSE_POSITIVE.value, datetime.now().isoformat(), finding_id))
            
            # Update cache
            if finding_id in self._findings_cache:
                self._findings_cache[finding_id].type = FindingType.FALSE_POSITIVE
                self._findings_cache[finding_id].updated_at = datetime.now()
                
        except Exception as e:
            logger.error(f"Failed to mark false positive: {e}")
    
    def _mark_confirmed(self, finding_id: str):
        """Mark a finding as confirmed"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    UPDATE findings 
                    SET confidence = ?, updated_at = ?
                    WHERE id = ?
                """, (1.0, datetime.now().isoformat(), finding_id))
            
            # Update cache
            if finding_id in self._findings_cache:
                self._findings_cache[finding_id].confidence = 1.0
                self._findings_cache[finding_id].updated_at = datetime.now()
                
        except Exception as e:
            logger.error(f"Failed to mark confirmed: {e}")
    
    def get_finding_statistics(self) -> Dict[str, Any]:
        """Get statistics about stored findings"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                stats = {}
                
                # Total findings
                cursor = conn.execute("SELECT COUNT(*) FROM findings")
                stats['total_findings'] = cursor.fetchone()[0]
                
                # Findings by type
                cursor = conn.execute("SELECT type, COUNT(*) FROM findings GROUP BY type")
                stats['by_type'] = dict(cursor.fetchall())
                
                # Findings by severity
                cursor = conn.execute("SELECT severity, COUNT(*) FROM findings GROUP BY severity")
                stats['by_severity'] = dict(cursor.fetchall())
                
                # Recent findings (last 7 days)
                cutoff_date = datetime.now() - timedelta(days=7)
                cursor = conn.execute("SELECT COUNT(*) FROM findings WHERE created_at > ?", 
                                    (cutoff_date.isoformat(),))
                stats['recent_findings'] = cursor.fetchone()[0]
                
                # Top URLs by finding count
                cursor = conn.execute("""
                    SELECT url, COUNT(*) as count 
                    FROM findings 
                    GROUP BY url 
                    ORDER BY count DESC 
                    LIMIT 10
                """)
                stats['top_urls'] = dict(cursor.fetchall())
                
                # Model performance
                cursor = conn.execute("SELECT model_used, COUNT(*) FROM findings GROUP BY model_used")
                stats['by_model'] = dict(cursor.fetchall())
                
                return stats
                
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {}
    
    def cleanup_old_findings(self):
        """Remove old findings based on retention policy"""
        try:
            cutoff_date = datetime.now() - timedelta(days=self.retention_days)
            
            with sqlite3.connect(self.db_path) as conn:
                # Delete old feedback first (foreign key constraint)
                cursor = conn.execute("""
                    DELETE FROM feedback 
                    WHERE finding_id IN (
                        SELECT id FROM findings WHERE created_at < ?
                    )
                """, (cutoff_date.isoformat(),))
                feedback_deleted = cursor.rowcount
                
                # Delete old findings
                cursor = conn.execute("""
                    DELETE FROM findings WHERE created_at < ?
                """, (cutoff_date.isoformat(),))
                findings_deleted = cursor.rowcount
                
                logger.info(f"Cleaned up {findings_deleted} old findings and {feedback_deleted} feedback entries")
                
                # Refresh cache
                self._findings_cache.clear()
                self._hash_index.clear()
                self._url_index.clear()
                self._load_cache()
                
        except Exception as e:
            logger.error(f"Failed to cleanup old findings: {e}")
    
    def export_findings(self, output_path: str, include_false_positives: bool = False):
        """Export findings to JSON file"""
        try:
            findings = []
            
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                query = "SELECT * FROM findings"
                if not include_false_positives:
                    query += " WHERE type != 'false_positive'"
                query += " ORDER BY created_at DESC"
                
                cursor = conn.execute(query)
                
                for row in cursor:
                    finding = self._row_to_finding(row)
                    findings.append(asdict(finding))
            
            export_data = {
                'exported_at': datetime.now().isoformat(),
                'total_findings': len(findings),
                'findings': findings
            }
            
            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            logger.info(f"Exported {len(findings)} findings to {output_path}")
            
        except Exception as e:
            logger.error(f"Failed to export findings: {e}")
    
    def is_duplicate_vulnerability(self, 
                                 url: str, 
                                 method: str, 
                                 vulnerability_type: str, 
                                 parameters: Dict[str, Any] = None) -> bool:
        """Check if a vulnerability is a duplicate"""
        parameters = parameters or {}
        finding_hash = self._calculate_finding_hash(url, method, vulnerability_type, parameters)
        return self.find_duplicate(finding_hash) is not None


# CLI interface for testing
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Memory Manager CLI")
    parser.add_argument("--stats", action="store_true", help="Show finding statistics")
    parser.add_argument("--cleanup", action="store_true", help="Cleanup old findings")
    parser.add_argument("--export", help="Export findings to JSON file")
    
    args = parser.parse_args()
    
    manager = MemoryManager()
    
    if args.stats:
        stats = manager.get_finding_statistics()
        print("Finding Statistics:")
        print(json.dumps(stats, indent=2))
    
    elif args.cleanup:
        manager.cleanup_old_findings()
        print("Cleanup completed")
    
    elif args.export:
        manager.export_findings(args.export)
        print(f"Findings exported to {args.export}")
    
    else:
        print("Please specify an action: --stats, --cleanup, or --export")
