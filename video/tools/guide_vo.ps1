# Synthesises a SCRATCH guide voiceover (one WAV per line) with the Windows built-in speech engine.
# Timing reference only - replace with a human or licensed voice for the final film.
# Usage: powershell -ExecutionPolicy Bypass -File video\tools\guide_vo.ps1 [-Rate 1]
param([int]$Rate = 1)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Speech
$root = Split-Path -Parent $PSScriptRoot
$lines = Get-Content -Raw -Encoding UTF8 (Join-Path $root "out\aman_gate_vo_lines.json") | ConvertFrom-Json
$dir = Join-Path $root "out\guide_vo"
New-Item -ItemType Directory -Force $dir | Out-Null

$synth = New-Object System.Speech.Synthesis.SpeechSynthesizer
$voice = $synth.GetInstalledVoices() | Where-Object { $_.VoiceInfo.Culture.Name -like "en-*" } | Select-Object -First 1
if ($voice) { $synth.SelectVoice($voice.VoiceInfo.Name) }
$synth.Rate = $Rate
$fmt = New-Object System.Speech.AudioFormat.SpeechAudioFormatInfo(48000, [System.Speech.AudioFormat.AudioBitsPerSample]::Sixteen, [System.Speech.AudioFormat.AudioChannel]::Mono)

foreach ($l in $lines) {
    # Spell the acronym so the engine does not say "a man".
    $spoken = $l.text -replace "AMAN Gate", "Ah-mahn Gate"
    $synth.SetOutputToWaveFile((Join-Path $dir "$($l.id).wav"), $fmt)
    $synth.Speak($spoken)
}
$synth.SetOutputToNull()
"voice=$($synth.Voice.Name) rate=$Rate lines=$($lines.Count) dir=$dir"
