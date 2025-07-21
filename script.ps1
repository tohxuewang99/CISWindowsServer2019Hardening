# WS2019_Hardening.ps1
# Interactive script for Windows Server 2019 Hardening

# ----------------------------------------------------------------------
# Function to display main menu and get user choice
# ----------------------------------------------------------------------
function Show-MainMenu {
    Clear-Host
    Write-Host "============================================="
    Write-Host " Windows Server 2019 Hardening Tool"
    Write-Host "============================================="
    Write-Host ""
    Write-Host "0. Exit"
    Write-Host "1. (R) Restore Default Settings"
    Write-Host "2. (MS) Member Server Hardening"
    Write-Host "3. (DC) Domain Controller Hardening"
    Write-Host ""
    
    $validChoices = @('0','1','2','3','r','restore','ms','dc','exit')
    
    do {
        $choice = Read-Host "Please select an option: "
        $choice = $choice.Trim().ToLower()
        
        if ($choice -notin $validChoices) {
            Write-Host "Invalid choice. Please try again: " -ForegroundColor Red
        }
    } while ($choice -notin $validChoices)
    
    # Normalize the choice to numeric value
    switch ($choice) {
        {$_ -in 'r','restore','1'} { return 'Restore' }
        {$_ -in 'ms','2'} { return "MS" }
        {$_ -in 'dc','3'} { return "DC" }
        {$_ -in 'exit','0'} { return "Exit" }
    }
}

# ----------------------------------------------------------------------
# Function to display hardening level menu
# ----------------------------------------------------------------------
function Get-HardeningLevel {
    Write-Host "`nPlease select hardening level:"
    Write-Host "0. (R) Return to main menu"
    Write-Host "1. (L1) Layer 1 Hardening"
    Write-Host "2. (L12) Layer 1 + Layer 2 Hardening"
    
    $validChoices = @('0','1','2','r','l12','l2','return')
    
    do {
        $choice = Read-Host "Enter your choice: "
        $choice = $choice.Trim().ToLower()
        
        if ($choice -notin $validChoices) {
            Write-Host "Invalid choice. Please enter again: " -ForegroundColor Red
        }
    } while ($choice -notin $validChoices)
    
    # Return the choice directly (let the caller handle "Return")
    return $choice
}

# ----------------------------------------------------------------------
# Main script logic
# ----------------------------------------------------------------------
function Main {
    do {
        $mainChoice = Show-MainMenu
        
        switch ($mainChoice) {
            'Restore' { # Restore Default Settings
                Write-Host "`nExecuting Restore Default Settings..."
                # Add your restore logic here
                Pause
            }
            'MS' { # Member Server Hardening
                do {
                    $levelChoice = Get-HardeningLevel
                    
                    if ($levelChoice -in '0','r','return') {
                        break # Return to main menu
                    }
                    
                    switch ($levelChoice) {
                        {$_ -in '1','l1'} { 
                            Write-Host "`nApplying Member Server - Layer 1 Hardening..."
                            # Process-RegistryValues -sourceFile "MS_L1.inf" -outputFile "LGPO_L1.txt"
                            Pause
                            break # Return to hardening level menu after completion
                        }
                        {$_ -in '2','l12'} { 
                            Write-Host "`nApplying Member Server - Layer 1 + Layer 2 Hardening..."
                            # Process-RegistryValues -sourceFile "MS_L2.inf" -outputFile "LGPO_L2.txt"
                            Pause
                            break # Return to hardening level menu after completion
                        }
                    }
                } while ($true)
            }
            'DC' { # Domain Controller Hardening
                do {
                    $levelChoice = Get-HardeningLevel
                    
                    if ($levelChoice -in '0','r','return') {
                        break # Break from current function and return to main menu
                    }
                    
                    switch ($levelChoice) {
                        {$_ -in '1','l1'} { 
                            Write-Host "`nApplying Domain Controller - Layer 1 Hardening..."
                            # Process-RegistryValues -sourceFile "DC_L1.inf" -outputFile "LGPO_DC_L1.txt"
                            Pause
                            break # Return to hardening level menu after completion
                        }
                        {$_ -in '2','l12'} { 
                            Write-Host "`nApplying Member Server - Layer 1 + Layer 2 Hardening..."
                            # Process-RegistryValues -sourceFile "DC_L2.inf" -outputFile "LGPO_DC_L2.txt"
                            Pause
                            break # Return to hardening level menu after completion
                        }
                    }
                } while ($true)
            }
            'Exit' { # Exit
                Write-Host "`nExiting..."
                exit
            }
        }
    } while ($true)
}

# ----------------------------------------------------------------------
# Registry processing function
# ----------------------------------------------------------------------
function Process-RegistryValues {
    param(
        [string]$sourceFile = "MS.inf",
        [string]$outputFile = "LGPO_text.txt"
    )

    Write-Host "Extracting registry values from source file..."

    # Read the source file
    $content = Get-Content -Path $sourceFile -Raw

    # Extract the section between [Registry Values] and [Privilege Rights]
    $pattern = '(?s)\[Registry Values\](.*?)\[Privilege Rights\]'
    $matches = [regex]::Matches($content, $pattern)

    if (-not $matches.Success) {
        Write-Host "Error: Could not find [Registry Values] section in the input file" -ForegroundColor Red
        exit
    }

    # Get the captured content and trim whitespace
    $registryValues = $matches.Groups[1].Value.Trim()
    $lines = $registryValues -split "`r`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    Write-Host "Registry values extracted successfully from source file"

    # Initialize output content
    $outputContent = @()
    $outputContent += "; ----------------------------------------------------------------------"
    $outputContent += "; PARSING Computer POLICY"
    $outputContent += "; Source file:  registry.pol"
    $outputContent += ""
    $outputContent += "Computer"

    # Process each line
    foreach ($line in $lines) {
        # Skip empty lines
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        # Split the line into path and value
        $parts = $line -split '=', 2
        $fullPath = $parts[0]
        $valuePart = $parts[1]

        # Remove "MACHINE\" prefix
        $fullPath = $fullPath -replace "^MACHINE\\", ""

        # Extract the key path and value name
        $lastBackslash = $fullPath.LastIndexOf('\')
        $keyPath = $fullPath.Substring(0, $lastBackslash)
        $valueName = $fullPath.Substring($lastBackslash + 1)

        # Determine the value type and data
        $typeAndData = $valuePart -split ',', 2
        $typeCode = $typeAndData[0]
        $data = $typeAndData[1]

        # Map type codes to simplified type names
        $typeMap = @{
            "1" = "SZ"
            "2" = "SZ"       # REG_EXPAND_SZ treated as SZ
            "3" = "BINARY"   # Need all CAPS for "BINARY", Value min 4 Hexa Decimal
            "4" = "DWORD"
            "7" = "MULTISZ"  # Can use \n, \r, \\, and end with \0 by default
        }

        $typeName = $typeMap[$typeCode]
        if (-not $typeName) {
            $typeName = "UNKNOWN" # Fallback for unexpected types
        }

        # Clean up the data formatting
        if ($data -match '^"(.*)"$') {
            $data = $matches[1]
        }

        if ($typeName -eq "BINARY") {
            # Remove any existing formatting
            $hexData = $data -replace '[^0-9A-Fa-f]', ''
            
            # Pad with zeros to ensure minimum 4 hex digits (2 bytes)
            if ($hexData.Length -lt 4) {
                $hexData = $hexData.PadRight(4, '0')
            }
            
            # Split into pairs of hex digits
            $hexPairs = @()
            for ($i = 0; $i -lt $hexData.Length; $i += 2) {
                $pair = $hexData.Substring($i, [Math]::Min(2, $hexData.Length - $i))
                $hexPairs += $pair.PadLeft(2, '0')
            }
            
            # Format with commas between pairs
            $formattedData = $hexPairs -join ','
            $data = $formattedData.ToLower()  # Use lowercase for consistency
        }

        # Add to output
        $outputContent += $keyPath
        $outputContent += $valueName
        $outputContent += "$($typeName):$($data)"
        $outputContent += ""
        $outputContent += "Computer"
    }

    # Remove the last unnecessary "Computer" line
    $outputContent = $outputContent[0..($outputContent.Count-2)]

    # Add completion markers
    $outputContent += ""
    $outputContent += "; PARSING COMPLETED."
    $outputContent += "; ----------------------------------------------------------------------"

    # Write the output file
    $outputContent | Out-File -FilePath $outputFile -Encoding utf8

    Write-Host "Conversion complete. Final output written to $outputFile"
}

# Start the script
Main