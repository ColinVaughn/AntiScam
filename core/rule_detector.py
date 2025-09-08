import re
import json
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

@dataclass
class DetectionRule:
    """Individual detection rule"""
    name: str
    pattern: str
    rule_type: str  # regex, keyword, composite
    confidence: float
    description: str
    enabled: bool = True
    case_sensitive: bool = False

@dataclass
class RuleResult:
    """Result of rule evaluation"""
    rule_name: str
    matched: bool
    confidence: float
    evidence: List[str]
    match_positions: List[Tuple[int, int]]

class RuleBasedDetector:
    """Rule-based scam detection system with configurable patterns"""
    
    def __init__(self):
        self.rules = self._initialize_default_rules()
        self.compiled_patterns = {}
        self._compile_patterns()
    
    def _initialize_default_rules(self) -> List[DetectionRule]:
        """Initialize default scam detection rules"""
        return [
            # Payment scam rules
            DetectionRule(
                name="venmo_cashapp_payment",
                pattern=r"\b(venmo|cashapp|cash\s*app|paypal\.me|payp(?:al)?\s*me)\b",
                rule_type="regex",
                confidence=0.4,
                description="Mentions payment services commonly used in scams",
                case_sensitive=False
            ),
            DetectionRule(
                name="phone_money_pattern",
                pattern=r"\b(\+?\d{7,15}|\(\d{3}\)\s*\d{3}-\d{4})\b.*\$\d{1,5}",
                rule_type="regex",
                confidence=0.6,
                description="Phone number followed by money amount",
                case_sensitive=False
            ),
            
            # Impersonation rules
            DetectionRule(
                name="admin_impersonation",
                pattern=r"@(admin|moderator|staff|support|official)",
                rule_type="regex",
                confidence=0.5,
                description="Attempts to impersonate staff members",
                case_sensitive=False
            ),
            DetectionRule(
                name="fake_verification",
                pattern=r"\b(verify|confirm|authenticate|validate)\s+(your\s+)?(account|identity|email)\b",
                rule_type="regex",
                confidence=0.3,
                description="Fake verification requests",
                case_sensitive=False
            ),
            
            # Urgency tactics
            DetectionRule(
                name="urgency_money",
                pattern=r"\b(urgent|asap|quickly|hurry|immediate)\b.*\b(money|pay|send|\$)\b",
                rule_type="regex",
                confidence=0.4,
                description="Urgency language combined with money requests",
                case_sensitive=False
            ),
            DetectionRule(
                name="limited_time_offer",
                pattern=r"\b(limited\s+time|expires?\s+(soon|today)|act\s+now|claim\s+(now|today))\b",
                rule_type="regex",
                confidence=0.2,
                description="Limited time pressure tactics",
                case_sensitive=False
            ),
            
            # Giveaway scams
            DetectionRule(
                name="giveaway_scam",
                pattern=r"\b(giveaway|free\s+(money|gift|prize)|win\s+\$\d+|contest)\b.*\b(dm|message|click|link)\b",
                rule_type="regex",
                confidence=0.3,
                description="Fake giveaway or contest scams",
                case_sensitive=False
            ),
            DetectionRule(
                name="nft_crypto_giveaway",
                pattern=r"\b(free\s+)?(nft|crypto|bitcoin|ethereum|token)\s+(giveaway|drop|airdrop)\b",
                rule_type="regex",
                confidence=0.4,
                description="Cryptocurrency or NFT giveaway scams",
                case_sensitive=False
            ),
            
            # Phishing patterns
            DetectionRule(
                name="account_suspended",
                pattern=r"\b(account|profile)\s+(suspended|locked|frozen|disabled|restricted)\b",
                rule_type="regex",
                confidence=0.3,
                description="Fake account suspension notifications",
                case_sensitive=False
            ),
            DetectionRule(
                name="click_here_phishing",
                pattern=r"\b(click\s+(here|link)|visit\s+link|go\s+to)\b.*\b(verify|confirm|secure|unlock)\b",
                rule_type="regex",
                confidence=0.4,
                description="Phishing link patterns",
                case_sensitive=False
            ),
            
            # Social engineering
            DetectionRule(
                name="dm_for_help",
                pattern=r"dm\s+(me|us)\s+(for|if)\s+(help|support|assistance|question)",
                rule_type="regex",
                confidence=0.2,
                description="Suspicious DM requests for help",
                case_sensitive=False
            ),
            DetectionRule(
                name="remote_access_request",
                pattern=r"\b(teamviewer|anydesk|remote\s+(access|desktop|control)|screen\s+share)\b",
                rule_type="regex",
                confidence=0.5,
                description="Remote access requests (common in tech support scams)",
                case_sensitive=False
            ),
            
            # Investment scams
            DetectionRule(
                name="investment_opportunity",
                pattern=r"\b(investment\s+opportunity|guaranteed\s+(profit|return)|double\s+your\s+money)\b",
                rule_type="regex",
                confidence=0.4,
                description="Investment scam language",
                case_sensitive=False
            ),
            DetectionRule(
                name="crypto_pump_dump",
                pattern=r"\b(pump|moon|to\s+the\s+moon|diamond\s+hands)\b.*\b(crypto|coin|token)\b",
                rule_type="regex",
                confidence=0.2,
                description="Cryptocurrency pump and dump language",
                case_sensitive=False
            ),
            
            # Composite rules (multiple conditions)
            DetectionRule(
                name="new_account_money_request",
                pattern="",  # Handled in composite logic
                rule_type="composite",
                confidence=0.5,
                description="New account requesting money"
            ),
            DetectionRule(
                name="urgent_verification_with_link",
                pattern="",  # Handled in composite logic
                rule_type="composite",
                confidence=0.6,
                description="Urgent verification request with suspicious link"
            )
        ]
    
    def _compile_patterns(self):
        """Compile regex patterns for efficiency"""
        for rule in self.rules:
            if rule.rule_type == "regex" and rule.pattern:
                flags = 0 if rule.case_sensitive else re.IGNORECASE
                try:
                    self.compiled_patterns[rule.name] = re.compile(rule.pattern, flags)
                except re.error as e:
                    logger.error(f"Invalid regex pattern for rule {rule.name}: {e}")
                    rule.enabled = False

    def evaluate_rules(self, text: str, metadata: Dict, ocr_text: str = "") -> Dict:
        """Evaluate all rules against text and return detection results"""
        results = {
            'total_confidence': 0.0,
            'triggered_rules': [],
            'rule_results': [],
            'is_scam': False,
            'evidence': []
        }
        
        # Combine text sources
        combined_text = f"{text} {ocr_text}".strip()
        
        # Evaluate individual rules
        for rule in self.rules:
            if not rule.enabled:
                continue
                
            if rule.rule_type == "regex":
                rule_result = self._evaluate_regex_rule(rule, combined_text)
            elif rule.rule_type == "composite":
                rule_result = self._evaluate_composite_rule(rule, combined_text, metadata)
            else:
                continue  # Skip unknown rule types
            
            results['rule_results'].append(rule_result)
            
            if rule_result.matched:
                results['triggered_rules'].append(rule.name)
                results['total_confidence'] += rule_result.confidence
                results['evidence'].extend(rule_result.evidence)
        
        # Apply confidence scaling (prevent over-confidence from multiple weak rules)
        results['total_confidence'] = min(results['total_confidence'], 1.0)
        
        # Scale down if too many weak rules triggered
        if len(results['triggered_rules']) > 3:
            scaling_factor = 0.85 ** (len(results['triggered_rules']) - 3)
            results['total_confidence'] *= scaling_factor
        
        # Determine if it's a scam based on confidence threshold
        results['is_scam'] = results['total_confidence'] >= 0.7
        
        return results
    
    def _evaluate_regex_rule(self, rule: DetectionRule, text: str) -> RuleResult:
        """Evaluate a regex-based rule"""
        pattern = self.compiled_patterns.get(rule.name)
        if not pattern:
            return RuleResult(rule.name, False, 0.0, [], [])
        
        matches = list(pattern.finditer(text))
        if not matches:
            return RuleResult(rule.name, False, 0.0, [], [])
        
        evidence = []
        match_positions = []
        
        for match in matches:
            evidence.append(match.group(0))
            match_positions.append((match.start(), match.end()))
        
        # Adjust confidence based on number of matches
        confidence = rule.confidence
        if len(matches) > 1:
            confidence = min(confidence * 1.2, 1.0)
        
        return RuleResult(
            rule_name=rule.name,
            matched=True,
            confidence=confidence,
            evidence=evidence,
            match_positions=match_positions
        )
    
    def _evaluate_composite_rule(self, rule: DetectionRule, text: str, metadata: Dict) -> RuleResult:
        """Evaluate composite rules that require multiple conditions"""
        if rule.name == "new_account_money_request":
            return self._evaluate_new_account_money_rule(rule, text, metadata)
        elif rule.name == "urgent_verification_with_link":
            return self._evaluate_urgent_verification_rule(rule, text, metadata)
        
        return RuleResult(rule.name, False, 0.0, [], [])
    
    def _evaluate_new_account_money_rule(self, rule: DetectionRule, text: str, metadata: Dict) -> RuleResult:
        """Evaluate new account + money request composite rule"""
        author_age_days = metadata.get('author_age_days', 999)
        
        # Account must be less than 3 days old
        if author_age_days >= 3:
            return RuleResult(rule.name, False, 0.0, [], [])
        
        # Must contain money-related terms
        money_pattern = re.compile(r'\b(money|pay|send|\$\d+|cash|payment)\b', re.IGNORECASE)
        money_matches = money_pattern.findall(text)
        
        if not money_matches:
            return RuleResult(rule.name, False, 0.0, [], [])
        
        evidence = [f"New account ({author_age_days} days old)"] + money_matches
        confidence = rule.confidence
        
        # Higher confidence for very new accounts
        if author_age_days < 1:
            confidence = min(confidence * 1.3, 1.0)
        
        return RuleResult(
            rule_name=rule.name,
            matched=True,
            confidence=confidence,
            evidence=evidence,
            match_positions=[]
        )
    
    def _evaluate_urgent_verification_rule(self, rule: DetectionRule, text: str, metadata: Dict) -> RuleResult:
        """Evaluate urgent verification + link composite rule"""
        text_lower = text.lower()
        
        # Must have urgency language
        urgency_words = ['urgent', 'immediately', 'asap', 'expires', 'limited time']
        has_urgency = any(word in text_lower for word in urgency_words)
        
        # Must have verification language
        verify_words = ['verify', 'confirm', 'authenticate', 'validate']
        has_verification = any(word in text_lower for word in verify_words)
        
        # Must have links
        has_links = metadata.get('has_links', False) or len(metadata.get('links', [])) > 0
        
        if not (has_urgency and has_verification and has_links):
            return RuleResult(rule.name, False, 0.0, [], [])
        
        evidence = []
        if has_urgency:
            found_urgency = [word for word in urgency_words if word in text_lower]
            evidence.extend(found_urgency)
        if has_verification:
            found_verify = [word for word in verify_words if word in text_lower]
            evidence.extend(found_verify)
        if has_links:
            evidence.append("contains_links")
        
        return RuleResult(
            rule_name=rule.name,
            matched=True,
            confidence=rule.confidence,
            evidence=evidence,
            match_positions=[]
        )
    
    def get_rule_by_name(self, name: str) -> Optional[DetectionRule]:
        """Get rule by name"""
        for rule in self.rules:
            if rule.name == name:
                return rule
        return None
    
    def add_custom_rule(self, rule: DetectionRule) -> bool:
        """Add a custom rule"""
        try:
            # Validate regex if applicable
            if rule.rule_type == "regex" and rule.pattern:
                flags = 0 if rule.case_sensitive else re.IGNORECASE
                compiled = re.compile(rule.pattern, flags)
                self.compiled_patterns[rule.name] = compiled
            
            self.rules.append(rule)
            logger.info(f"Added custom rule: {rule.name}")
            return True
        except re.error as e:
            logger.error(f"Invalid regex pattern for rule {rule.name}: {e}")
            return False
    
    def disable_rule(self, rule_name: str) -> bool:
        """Disable a rule by name"""
        rule = self.get_rule_by_name(rule_name)
        if rule:
            rule.enabled = False
            logger.info(f"Disabled rule: {rule_name}")
            return True
        return False
    
    def enable_rule(self, rule_name: str) -> bool:
        """Enable a rule by name"""
        rule = self.get_rule_by_name(rule_name)
        if rule:
            rule.enabled = True
            logger.info(f"Enabled rule: {rule_name}")
            return True
        return False
    
    def get_enabled_rules(self) -> List[str]:
        """Get list of enabled rule names"""
        return [rule.name for rule in self.rules if rule.enabled]
    
    def export_rules(self) -> str:
        """Export rules to JSON format"""
        rules_data = []
        for rule in self.rules:
            rules_data.append({
                'name': rule.name,
                'pattern': rule.pattern,
                'rule_type': rule.rule_type,
                'confidence': rule.confidence,
                'description': rule.description,
                'enabled': rule.enabled,
                'case_sensitive': rule.case_sensitive
            })
        return json.dumps(rules_data, indent=2)
    
    def import_rules(self, rules_json: str) -> int:
        """Import rules from JSON format, returns number of rules imported"""
        try:
            rules_data = json.loads(rules_json)
            imported_count = 0
            
            for rule_data in rules_data:
                rule = DetectionRule(
                    name=rule_data['name'],
                    pattern=rule_data['pattern'],
                    rule_type=rule_data['rule_type'],
                    confidence=rule_data['confidence'],
                    description=rule_data['description'],
                    enabled=rule_data.get('enabled', True),
                    case_sensitive=rule_data.get('case_sensitive', False)
                )
                
                # Don't import if rule already exists
                if not self.get_rule_by_name(rule.name):
                    if self.add_custom_rule(rule):
                        imported_count += 1
            
            return imported_count
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to import rules: {e}")
            return 0
