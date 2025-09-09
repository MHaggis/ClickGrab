# ClickFix Techniques YAML Schema

This document defines the schema for ClickFix technique YAML files.

## Root Level Fields

```yaml
name: string                    # Required: Tool/executable name (e.g., "cmd.exe", "DxDiag.exe")
added_at: string               # Required: Date added in YYYY-MM-DD format
platform: string               # Required: Target platform ("windows", "mac", "linux")
presentation: string           # Required: Interface type ("gui", "cli")
info: string                   # Optional: Description of the tool (supports Markdown)
```

## Lures Section

Each technique can have multiple lures (social engineering scenarios):

```yaml
lures:
  - nickname: string           # Required: Short name for the lure
    added_at: string          # Required: Date added in YYYY-MM-DD format
    contributor:              # Required: Information about who contributed this lure
      name: string            # Required: Contributor's name
      handle: string          # Optional: Social media handle
      contacts:               # Optional: Contact information
        linkedin: string      # Optional: LinkedIn profile
        twitter: string       # Optional: Twitter handle
        youtube: string       # Optional: YouTube channel
        github: string        # Optional: GitHub username
    preamble: string          # Optional: Introduction text (supports Markdown)
    steps:                    # Required: List of steps for the lure
      - string                # Each step supports Markdown formatting
    capabilities:             # Optional: List of capabilities this lure exploits
      - string                # e.g., "UAC", "MOTW", "File Explorer"
    epilogue: string          # Optional: Conclusion text (supports Markdown)
    references:               # Optional: List of reference URLs
      - string                # URLs to documentation, examples, or related resources
    mitigations:              # Optional: List of mitigation strategies
      - string                # Specific mitigation advice for this lure
```

## Example Complete Schema

```yaml
name: DxDiag.exe
added_at: 2025-01-08
platform: windows
presentation: gui
info: >
  `DxDiag.exe` is the **DirectX Diagnostic Tool** that provides detailed information about DirectX components and drivers on Windows systems.

lures:
  - nickname: "Fix Your Graphics Driver"
    added_at: "2025-01-08"
    contributor:
      name: "John Hammond"
      handle: "johnhammond"
      contacts:
        linkedin: "johnhammond"
        twitter: "_johnhammond"
        youtube: "@_JohnHammond"
        github: "John Hammond"
    preamble: >
      Your graphics driver is out of date! Follow these steps to update it.
    steps:
      - "Press **Win-R** on your keyboard"
      - "Type **`DxDiag`** and press **Enter**"
      - "Click **Save All Information**"
      - "Press **Ctrl-L** to focus the address bar"
      - "Press **Ctrl-V** to paste our configuration"
      - "Press **Enter** to submit"
    capabilities:
      - MOTW
      - File Explorer
    epilogue: >
      Once you have completed the steps you can continue with your work.
    references:
      - "https://docs.microsoft.com/en-us/windows/win32/directx/dxdiag"
      - "https://attack.mitre.org/techniques/T1059/"
      - "https://attack.mitre.org/techniques/T1082/"
      - "https://any.run/sandbox/example-analysis"
    mitigations:
      - "Verify caller identity through official channels"
      - "Never run commands from unsolicited technical support"
      - "Use official support channels only"
      - "Be suspicious of requests to run system tools"
```

## Field Descriptions

### Required Fields
- **name**: The executable or tool name
- **added_at**: ISO date when the technique was added
- **platform**: Target operating system
- **presentation**: User interface type
- **lures**: At least one lure must be defined
- **nickname**: Short descriptive name for the lure
- **steps**: List of steps the victim is instructed to follow
- **contributor.name**: Name of the person who contributed this lure

### Optional Fields
- **info**: Tool description (supports Markdown)
- **preamble**: Introduction text for the lure (supports Markdown)
- **epilogue**: Conclusion text for the lure (supports Markdown)
- **capabilities**: List of system capabilities exploited
- **references**: URLs to documentation, examples, or analysis
- **mitigations**: Specific mitigation strategies
- **contributor.handle**: Social media handle
- **contributor.contacts**: Various contact methods

### Markdown Support
The following fields support Markdown formatting:
- `info`
- `preamble`
- `steps` (individual steps)
- `epilogue`
- `mitigations` (individual mitigations)

### Capabilities
Common capability values:
- **UAC**: User Account Control bypass
- **MOTW**: Mark of the Web bypass
- **File Explorer**: File Explorer integration
- **CLI**: Command Line Interface access
- **GUI**: Graphical User Interface access

### References
References can include:
- Official documentation
- MITRE ATT&CK techniques
- Sandbox analysis reports
- Security research papers
- Related tools or techniques
