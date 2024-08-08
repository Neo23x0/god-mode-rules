
/*
      _____        __  __  ___        __      
     / ___/__  ___/ / /  |/  /__  ___/ /__    
    / (_ / _ \/ _  / / /|_/ / _ \/ _  / -_)   
    \___/\___/\_,_/_/_/__/_/\___/\_,_/\__/    
     \ \/ / _ | / _ \/ _ |   / _ \__ __/ /__  
      \  / __ |/ , _/ __ |  / , _/ // / / -_) 
      /_/_/ |_/_/|_/_/ |_| /_/|_|\_,_/_/\__/  
   
   Florian Roth - v0.8.1 August 2024 - Merry Christmas!

   The 'God Mode Rule' is a proof-of-concept YARA rule designed to 
   identify a wide range of security threats. It includes detections for 
   Mimikatz usage, Metasploit Meterpreter payloads, PowerShell obfuscation 
   and encoded payloads, various malware indicators, and specific hacking 
   tools. This rule also targets ransomware behaviors, such as 
   shadow copy deletion commands, and patterns indicative of crypto mining. 
   It's further enhanced to detect obfuscation techniques and signs of 
   advanced persistent threats (APTs), including unique strings from 
   well-known hacking tools and frameworks. 
*/

rule IDDQD_God_Mode_Rule {
   meta:
      description = "Detects a wide array of cyber threats, from malware and ransomware to advanced persistent threats (APTs)"
      author = "Florian Roth"
      reference = "Internal Research - get a god mode rule set with THOR by Nextron Systems"
      date = "2019-05-15"
      modified = "2024-01-12"
      score = 60
   strings:
      $ = "sekurlsa::logonpasswords" ascii wide nocase           /* Mimikatz Command */
      $ = "ERROR kuhl" wide xor                                  /* Mimikatz Error */
      $ = " -w hidden " ascii wide nocase                        /* Power Shell Params */
      $ = "Koadic." ascii                                        /* Koadic Framework */
      $ = "ReflectiveLoader" fullword ascii wide xor             /* Generic - Common Export Name */
      $ = "%s as %s\\%s: %d" ascii xor                           /* CobaltStrike indicator */
      $ = "[System.Convert]::FromBase64String(" ascii            /* PowerShell - Base64 encoded payload */
      $ = "/meterpreter/" ascii xor                              /* Metasploit Framework - Meterpreter */
      $ = / -[eE][decoman]{0,41} ['"]?(JAB|SUVYI|aWV4I|SQBFAFgA|aQBlAHgA|cgBlAG)/ ascii wide  /* PowerShell encoded code */
      $ = /  (sEt|SEt|SeT|sET|seT)  / ascii wide                 /* Casing Obfuscation */
      $ = ");iex " nocase ascii wide                             /* PowerShell - compact code */ 
      $ = "Nir Sofer" fullword wide                              /* Hack Tool Producer */
      $ = "impacket." ascii                                      /* Impacket Library */
      $ = /\[[\+\-!E]\] (exploit|target|vulnerab|shell|inject)/ nocase  /* Hack Tool Output Pattern */
      $ = "0000FEEDACDC}" ascii wide                             /* Squiblydoo - Class ID */
      $ = "vssadmin delete shadows" ascii nocase                 /* Shadow Copy Deletion via vssadmin - often used in ransomware */
      $ = ".exe delete shadows" ascii nocase                     /* Shadow Copy Deletion via vssadmin - often used in ransomware */
      $ = " shadowcopy delete" ascii wide nocase                 /* Shadow Copy Deletion via WMIC - often used in ransomware */
      $ = " delete catalog -quiet" ascii wide nocase             /* Shadow Copy Deletion via wbadmin - often used in ransomware */
      $ = "stratum+tcp://" ascii wide                            /* Stratum Address - used in Crypto Miners */
      $ = /\\(Debug|Release)\\(Key[lL]og|[Ii]nject|Steal|By[Pp]ass|Amsi|Dropper|Loader|CVE\-)/  /* Typical PDB strings found in malware or hack tools */
      $ = /(Dropper|Bypass|Injection|Potato)\.pdb/ nocase        /* Typical PDP strings found in hack tools */
      $ = "Mozilla/5.0" xor(0x01-0xff) ascii wide                /* XORed Mozilla user agent - often found in implants */
      $ = "amsi.dllATVSH" ascii xor                              /* Havoc C2 */
      $ = "BeaconJitter" xor                                     /* Sliver */
      $ = "main.Merlin" ascii fullword                           /* Merlin C2 */
      $ = "\x48\x83\xec\x50\x4d\x63\x68\x3c\x48\x89\x4d\x10" xor /* Brute Ratel C4 */
      $ = "}{0}\"-f " ascii wide                                 /* PowerShell obfuscation - format string */
      $ = "HISTORY=/dev/null" ascii                              /* Linux HISTORY tampering - found in many samples */
      $ = " /tmp/x;" ascii                                       /* Often used in malicious linux scripts */
      $ = /comsvcs(\.dll)?[, ]{1,2}(MiniDump|#24)/               /* Process dumping method using comsvcs.dll's MiniDump */
      $ = "AmsiScanBuffer" base64 base64wide                     /* AMSI Bypass */
      $ = "AmsiScanBuffer" xor(0x01-0xff)                        /* AMSI Bypass */
      $ = "%%%%%%%%%%%######%%%#%%####%  &%%**#" ascii wide xor  /* SeatBelt */
   condition:
      1 of them
}
