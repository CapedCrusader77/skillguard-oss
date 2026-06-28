# Severity Levels
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"

# Risk Categories
CAT_COMMAND = "COMMAND_EXECUTION"
CAT_FILE = "FILE_SYSTEM"
CAT_NETWORK = "NETWORK"
CAT_SECRET = "SECRET_ACCESS"

# Scoring weights based on specific requirements
RULE_SCORES = {
    # Python Command Execution
    "subprocess.Popen": 25,
    "subprocess.run": 20,
    "subprocess.call": 20,
    "os.system": 20,
    "shell=True": 30,
    
    # Python Network Detection
    "requests.post": 10,
    "requests.get": 5,
    "requests.put": 10,
    "requests.delete": 10,
    "httpx": 10,
    "urllib": 5,
    "socket": 10,
    
    # Python Filesystem Detection
    "open()": 5,
    "pathlib.Path": 5,
    "os.walk": 10,
    "glob.glob": 5,
    
    # Python Secret/Env Detection
    "os.getenv": 5,
    "os.environ": 5,

    # JavaScript/TypeScript Command Execution
    "child_process.exec": 20,
    "child_process.spawn": 25,
    "child_process.execSync": 20,

    # JavaScript/TypeScript Filesystem Detection
    "fs.readFile": 5,
    "fs.writeFile": 5,
    "fs.open": 5,

    # JavaScript/TypeScript Network Detection
    "fetch": 5,
    "axios": 10,
    "http.request": 5,
    "https.request": 5,

    # JavaScript/TypeScript Secret/Env Detection
    "process.env": 5,

    # Dart/Flutter Command Execution
    "dart.Process.run": 25,
    "dart.Process.start": 25,

    # Dart/Flutter Filesystem Detection
    "dart.File": 5,
    "dart.Directory": 5,

    # Dart/Flutter Network Detection
    "dart.http.get": 5,
    "dart.http.post": 10,
    "dart.Dio": 10,

    # Dart/Flutter Environment Detection
    "dart.Platform.environment": 5,
}

# Mapping of rule identifiers/methods to Rule IDs and categories
RULE_METADATA = {
    # Python
    "subprocess.Popen": {"id": "CMD001", "severity": SEVERITY_HIGH, "category": CAT_COMMAND, "message": "subprocess.Popen detected"},
    "subprocess.run": {"id": "CMD002", "severity": SEVERITY_HIGH, "category": CAT_COMMAND, "message": "subprocess.run detected"},
    "subprocess.call": {"id": "CMD003", "severity": SEVERITY_HIGH, "category": CAT_COMMAND, "message": "subprocess.call detected"},
    "os.system": {"id": "CMD004", "severity": SEVERITY_HIGH, "category": CAT_COMMAND, "message": "os.system detected"},
    "shell=True": {"id": "CMD005", "severity": SEVERITY_HIGH, "category": CAT_COMMAND, "message": "subprocess executed with shell=True"},
    
    "requests.post": {"id": "NET001", "severity": SEVERITY_MEDIUM, "category": CAT_NETWORK, "message": "requests.post detected"},
    "requests.get": {"id": "NET002", "severity": SEVERITY_LOW, "category": CAT_NETWORK, "message": "requests.get detected"},
    "requests.put": {"id": "NET003", "severity": SEVERITY_MEDIUM, "category": CAT_NETWORK, "message": "requests.put detected"},
    "requests.delete": {"id": "NET004", "severity": SEVERITY_MEDIUM, "category": CAT_NETWORK, "message": "requests.delete detected"},
    "httpx": {"id": "NET005", "severity": SEVERITY_MEDIUM, "category": CAT_NETWORK, "message": "httpx call detected"},
    "urllib": {"id": "NET006", "severity": SEVERITY_LOW, "category": CAT_NETWORK, "message": "urllib call detected"},
    "socket": {"id": "NET007", "severity": SEVERITY_MEDIUM, "category": CAT_NETWORK, "message": "socket connection detected"},
    
    "open()": {"id": "FIL001", "severity": SEVERITY_LOW, "category": CAT_FILE, "message": "open() detected"},
    "pathlib.Path": {"id": "FIL002", "severity": SEVERITY_LOW, "category": CAT_FILE, "message": "pathlib.Path detected"},
    "os.walk": {"id": "FIL003", "severity": SEVERITY_MEDIUM, "category": CAT_FILE, "message": "os.walk detected"},
    "glob.glob": {"id": "FIL004", "severity": SEVERITY_LOW, "category": CAT_FILE, "message": "glob.glob detected"},
    
    "os.getenv": {"id": "SEC001", "severity": SEVERITY_LOW, "category": CAT_SECRET, "message": "os.getenv detected"},
    "os.environ": {"id": "SEC002", "severity": SEVERITY_LOW, "category": CAT_SECRET, "message": "os.environ detected"},

    # JavaScript/TypeScript
    "child_process.exec": {"id": "CMD101", "severity": SEVERITY_HIGH, "category": CAT_COMMAND, "message": "child_process.exec detected"},
    "child_process.spawn": {"id": "CMD102", "severity": SEVERITY_HIGH, "category": CAT_COMMAND, "message": "child_process.spawn detected"},
    "child_process.execSync": {"id": "CMD103", "severity": SEVERITY_HIGH, "category": CAT_COMMAND, "message": "child_process.execSync detected"},

    "fs.readFile": {"id": "FIL101", "severity": SEVERITY_LOW, "category": CAT_FILE, "message": "fs.readFile detected"},
    "fs.writeFile": {"id": "FIL102", "severity": SEVERITY_LOW, "category": CAT_FILE, "message": "fs.writeFile detected"},
    "fs.open": {"id": "FIL103", "severity": SEVERITY_LOW, "category": CAT_FILE, "message": "fs.open detected"},

    "fetch": {"id": "NET101", "severity": SEVERITY_LOW, "category": CAT_NETWORK, "message": "fetch call detected"},
    "axios": {"id": "NET102", "severity": SEVERITY_MEDIUM, "category": CAT_NETWORK, "message": "axios call detected"},
    "http.request": {"id": "NET103", "severity": SEVERITY_LOW, "category": CAT_NETWORK, "message": "http.request detected"},
    "https.request": {"id": "NET104", "severity": SEVERITY_LOW, "category": CAT_NETWORK, "message": "https.request detected"},

    "process.env": {"id": "SEC102", "severity": SEVERITY_LOW, "category": CAT_SECRET, "message": "process.env access detected"},

    # Dart/Flutter
    "dart.Process.run":          {"id": "CMD201", "severity": SEVERITY_HIGH,   "category": CAT_COMMAND, "message": "Process.run detected (Dart command execution)"},
    "dart.Process.start":        {"id": "CMD202", "severity": SEVERITY_HIGH,   "category": CAT_COMMAND, "message": "Process.start detected (Dart command execution)"},

    "dart.File":                 {"id": "FIL201", "severity": SEVERITY_LOW,    "category": CAT_FILE,    "message": "File() constructor detected (Dart filesystem access)"},
    "dart.Directory":            {"id": "FIL202", "severity": SEVERITY_LOW,    "category": CAT_FILE,    "message": "Directory() constructor detected (Dart filesystem access)"},

    "dart.http.get":             {"id": "NET201", "severity": SEVERITY_LOW,    "category": CAT_NETWORK, "message": "http.get detected (Dart network request)"},
    "dart.http.post":            {"id": "NET202", "severity": SEVERITY_MEDIUM, "category": CAT_NETWORK, "message": "http.post detected (Dart network request)"},
    "dart.Dio":                  {"id": "NET203", "severity": SEVERITY_MEDIUM, "category": CAT_NETWORK, "message": "Dio client detected (Dart HTTP client)"},

    "dart.Platform.environment": {"id": "SEC201", "severity": SEVERITY_LOW,    "category": CAT_SECRET,  "message": "Platform.environment accessed (Dart env vars)"},
}
