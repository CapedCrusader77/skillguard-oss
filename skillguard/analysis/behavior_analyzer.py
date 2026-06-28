import os
import re
from pathlib import Path
from typing import List
from skillguard.analysis.models import BehaviorProfile
from skillguard.models.finding import Finding
from skillguard.core.repository_discovery import get_scan_targets

class BehaviorAnalyzer:
    def analyze_behavior(self, repo_path: Path, findings: List[Finding]) -> BehaviorProfile:
        filesystem = False
        network = False
        database = False
        email = False
        browser = False
        credentials = False

        # 1. Analyze findings for implicit permissions
        for f in findings:
            cat = f.category.upper()
            fid = f.id.upper()
            
            if cat == "FILE_SYSTEM" or fid in {"DKR005"}:
                filesystem = True
            
            if cat == "NETWORK" or fid in {"NET201"}:
                network = True
                
            if cat == "SECRET_ACCESS" or fid in {"GHA003", "SEC101", "SEC102"}:
                credentials = True

        # 2. Discover packages/modules inside source files
        try:
            # If target is a file, analyze parent directory to search workspace dependencies
            scan_path = repo_path.parent if repo_path.is_file() else repo_path
            files, _, _ = get_scan_targets(scan_path)
        except Exception:
            files = []

        re_db = re.compile(r"\b(sqlite3|sqlite|mysql|pg|prisma|sqlalchemy|pymongo|psycopg2|redis)\b", re.IGNORECASE)
        re_email = re.compile(r"\b(smtplib|email|nodemailer|sendgrid|mailchimp)\b", re.IGNORECASE)
        re_browser = re.compile(r"\b(playwright|puppeteer|selenium|browser_use|webdriver|browser_cookie3)\b", re.IGNORECASE)
        
        for file_path in files:
            if file_path.suffix.lower() not in {".py", ".js", ".ts", ".json", ".txt"}:
                continue
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            lines = content.splitlines()
            for line in lines:
                clean = line.strip()
                if not clean or clean.startswith("#") or clean.startswith("//"):
                    continue
                
                # Check DB imports / calls
                if re_db.search(clean) and ("import" in clean or "require" in clean):
                    database = True
                # Check Email imports / calls
                if re_email.search(clean) and ("import" in clean or "require" in clean):
                    email = True
                # Check Browser automation imports / calls
                if re_browser.search(clean) and ("import" in clean or "require" in clean):
                    browser = True

                # Code references
                if "sqlite3.connect" in clean or "prisma.user" in clean or "mongoose.connect" in clean:
                    database = True
                if "smtplib.SMTP" in clean or "nodemailer.createTransport" in clean:
                    email = True
                if "chromium.launch" in clean or "webdriver.Chrome" in clean or "playwright.async_api" in clean:
                    browser = True

        return BehaviorProfile(
            filesystem_access=filesystem,
            network_access=network,
            database_access=database,
            email_access=email,
            browser_automation=browser,
            credential_access=credentials
        )
