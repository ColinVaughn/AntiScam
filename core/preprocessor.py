import re
import unicodedata
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, unquote
import unidecode
import logging

logger = logging.getLogger(__name__)

class TextPreprocessor:
    """Handles text normalization, link extraction, and obfuscation detection"""
    
    def __init__(self):
        # Common homoglyph mappings
        self.homoglyphs = {
            # Cyrillic to Latin
            'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y',
            'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
            'Р': 'P', 'С': 'C', 'Т': 'T', 'У': 'Y', 'Х': 'X',
            # Greek to Latin
            'α': 'a', 'β': 'b', 'γ': 'y', 'δ': 'd', 'ε': 'e', 'ζ': 'z', 'η': 'h',
            'θ': 'th', 'ι': 'i', 'κ': 'k', 'λ': 'l', 'μ': 'm', 'ν': 'n', 'ξ': 'x',
            'ο': 'o', 'π': 'p', 'ρ': 'r', 'σ': 's', 'τ': 't', 'υ': 'u', 'φ': 'f',
            'χ': 'x', 'ψ': 'ps', 'ω': 'w',
            # Common unicode tricks
            '０': '0', '１': '1', '２': '2', '３': '3', '４': '4', '５': '5',
            '６': '6', '７': '7', '８': '8', '９': '9',
        }
        
        # Leetspeak mappings
        self.leetspeak = {
            '3': 'e', '4': 'a', '5': 's', '7': 't', '0': 'o', '1': 'i', '!': 'i',
            '@': 'a', '$': 's', '|': 'l', '8': 'b', '9': 'g', '6': 'g',
            '+': 't', '<': 'c', '()': 'o', '[]': 'o', '{}': 'o'
        }
        
        # URL shorteners (common ones used in scams)
        self.url_shorteners = {
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link',
            'tiny.cc', 'lnkd.in', 'buff.ly', 'ift.tt', 'is.gd', 'cli.gs',
            'u.to', 'ur1.ca', 'x.co', 'qr.ae', 'cutt.ly', 'rb.gy'
        }
        
        # Common scam keywords for quick detection
        self.scam_keywords = {
            'payment': ['venmo', 'cashapp', 'paypal', 'zelle', 'applepay', 'googlepay'],
            'urgency': ['urgent', 'asap', 'quickly', 'hurry', 'expire', 'limited time'],
            'impersonation': ['admin', 'moderator', 'staff', 'support', 'official'],
            'giveaway': ['giveaway', 'free', 'win', 'prize', 'contest', 'claim'],
            'verification': ['verify', 'confirm', 'authenticate', 'validate'],
            'phishing': ['login', 'password', 'account', 'suspended', 'locked'],
            'crypto': ['bitcoin', 'ethereum', 'crypto', 'wallet', 'nft', 'token']
        }
        
        # Link extraction patterns
        self.url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        self.domain_pattern = re.compile(
            r'(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})'
        )

    def normalize_text(self, text: str) -> str:
        """Comprehensive text normalization"""
        if not text:
            return ""
        
        # Remove zero-width characters and soft hyphens
        text = re.sub(r'[\u200b-\u200f\u2060\u00ad]', '', text)
        
        # Normalize unicode
        text = unicodedata.normalize('NFKC', text)
        
        # Replace homoglyphs
        for char, replacement in self.homoglyphs.items():
            text = text.replace(char, replacement)
        
        # Convert common leetspeak
        for leet, normal in self.leetspeak.items():
            # Use word boundaries to avoid false positives
            text = re.sub(rf'\b{re.escape(leet)}\b', normal, text, flags=re.IGNORECASE)
        
        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        return text

    def extract_links(self, text: str) -> List[Dict[str, str]]:
        """Extract and analyze links from text"""
        links = []
        
        # Find URLs
        for match in self.url_pattern.finditer(text):
            url = match.group(0)
            parsed = urlparse(url)
            
            link_info = {
                'url': url,
                'domain': parsed.netloc.lower(),
                'path': parsed.path,
                'is_shortener': parsed.netloc.lower() in self.url_shorteners,
                'position': match.start()
            }
            
            # Calculate domain entropy (suspicious domains often have high entropy)
            link_info['domain_entropy'] = self._calculate_entropy(parsed.netloc)
            
            # Check for suspicious patterns
            link_info['suspicious_patterns'] = self._check_suspicious_domain_patterns(parsed.netloc)
            
            links.append(link_info)
        
        # Find bare domains (without http://)
        for match in self.domain_pattern.finditer(text):
            domain = match.group(0).lower()
            if not any(link['domain'] == domain for link in links):
                link_info = {
                    'url': f'http://{domain}',
                    'domain': domain,
                    'path': '',
                    'is_shortener': domain in self.url_shorteners,
                    'position': match.start(),
                    'domain_entropy': self._calculate_entropy(domain),
                    'suspicious_patterns': self._check_suspicious_domain_patterns(domain)
                }
                links.append(link_info)
        
        return links

    def extract_features(self, text: str, metadata: Dict) -> Dict:
        """Extract comprehensive features for detection"""
        normalized_text = self.normalize_text(text)
        links = self.extract_links(text)
        
        features = {
            'original_text': text,
            'normalized_text': normalized_text,
            'text_length': len(text),
            'normalized_length': len(normalized_text),
            'links': links,
            'link_count': len(links),
            'shortener_count': sum(1 for link in links if link['is_shortener']),
            'suspicious_domains': sum(1 for link in links if link['suspicious_patterns']),
            'high_entropy_domains': sum(1 for link in links if link['domain_entropy'] > 3.5),
        }
        
        # Add keyword analysis
        features['keyword_matches'] = self._analyze_keywords(normalized_text)
        
        # Add suspicious patterns
        features['suspicious_patterns'] = self._detect_suspicious_patterns(normalized_text)
        
        # Add obfuscation indicators
        features['obfuscation_score'] = self._calculate_obfuscation_score(text, normalized_text)
        
        # Add metadata
        features['metadata'] = metadata
        
        return features

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        from collections import Counter
        import math
        
        counts = Counter(text)
        length = len(text)
        
        entropy = 0.0
        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy

    def _check_suspicious_domain_patterns(self, domain: str) -> List[str]:
        """Check for suspicious patterns in domain names"""
        patterns = []
        
        # Too many hyphens
        if domain.count('-') > 3:
            patterns.append('excessive_hyphens')
        
        # Suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.cc', '.pw', '.top']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            patterns.append('suspicious_tld')
        
        # Mixed character sets
        if any(ord(c) > 127 for c in domain):
            patterns.append('non_ascii_chars')
        
        # Very long subdomains
        parts = domain.split('.')
        if any(len(part) > 20 for part in parts):
            patterns.append('long_subdomain')
        
        # Homograph attacks
        if any(c in self.homoglyphs for c in domain):
            patterns.append('homograph_chars')
        
        return patterns

    def _analyze_keywords(self, text: str) -> Dict[str, List[str]]:
        """Analyze text for scam-related keywords"""
        text_lower = text.lower()
        matches = {}
        
        for category, keywords in self.scam_keywords.items():
            found = []
            for keyword in keywords:
                if keyword in text_lower:
                    found.append(keyword)
            if found:
                matches[category] = found
        
        return matches

    def _detect_suspicious_patterns(self, text: str) -> List[str]:
        """Detect suspicious patterns in text"""
        patterns = []
        text_lower = text.lower()
        
        # Phone number + money pattern
        phone_money_pattern = r'\b(\+?\d{7,15}|\(\d{3}\)\s*\d{3}-\d{4})\b.*\$\d{1,5}'
        if re.search(phone_money_pattern, text):
            patterns.append('phone_money_pattern')
        
        # Impersonation patterns
        if re.search(r'@(admin|moderator|staff|support)', text_lower):
            patterns.append('impersonation_mention')
        
        # Urgency + money
        urgency_money = r'(urgent|asap|quickly|hurry).*(money|\$|pay|send)'
        if re.search(urgency_money, text_lower):
            patterns.append('urgency_money')
        
        # DM requests with payment
        dm_payment = r'(dm\s+me|direct\s+message).*(pay|money|send|\$)'
        if re.search(dm_payment, text_lower):
            patterns.append('dm_payment_request')
        
        # Verification scams
        verify_scam = r'(verify|confirm|authenticate).*(account|click|link)'
        if re.search(verify_scam, text_lower):
            patterns.append('verification_scam')
        
        return patterns

    def _calculate_obfuscation_score(self, original: str, normalized: str) -> float:
        """Calculate how much the text was obfuscated"""
        if not original:
            return 0.0
        
        # Compare lengths
        length_diff = abs(len(original) - len(normalized)) / len(original)
        
        # Count special characters
        special_chars = sum(1 for c in original if not c.isalnum() and not c.isspace())
        special_ratio = special_chars / len(original)
        
        # Count unicode substitutions
        unicode_subs = sum(1 for c in original if ord(c) > 127)
        unicode_ratio = unicode_subs / len(original) if original else 0
        
        # Combine factors
        obfuscation_score = (length_diff * 0.3) + (special_ratio * 0.4) + (unicode_ratio * 0.3)
        
        return min(obfuscation_score, 1.0)

    def quick_scam_check(self, text: str, metadata: Dict) -> Tuple[bool, str, float]:
        """Quick rule-based scam detection for fast path"""
        normalized = self.normalize_text(text)
        text_lower = normalized.lower()
        
        # Check for obvious scam patterns
        confidence = 0.0
        reasons = []
        
        # Payment + urgency + new account
        if any(payment in text_lower for payment in ['venmo', 'cashapp', 'paypal']):
            confidence += 0.3
            reasons.append('payment_service_mentioned')
            
            if any(urgent in text_lower for urgent in ['urgent', 'asap', 'quickly']):
                confidence += 0.3
                reasons.append('urgency_language')
        
        # Impersonation attempt
        if '@admin' in text_lower or '@moderator' in text_lower:
            confidence += 0.4
            reasons.append('admin_impersonation')
        
        # Suspicious links
        links = self.extract_links(text)
        shorteners = [link for link in links if link['is_shortener']]
        if shorteners:
            confidence += 0.2
            reasons.append('url_shortener')
        
        # Phone + money pattern
        if re.search(r'\b(\+?\d{7,15}|\(\d{3}\)\s*\d{3}-\d{4})\b.*\$\d{1,5}', text):
            confidence += 0.5
            reasons.append('phone_money_pattern')
        
        # New account with money request
        author_age_days = metadata.get('author_age_days', 999)
        if author_age_days < 1 and any(word in text_lower for word in ['money', 'pay', 'send', '$']):
            confidence += 0.3
            reasons.append('new_account_money_request')
        
        is_scam = confidence >= 0.7
        reason = '; '.join(reasons) if reasons else 'no_quick_rules_triggered'
        
        return is_scam, reason, confidence
