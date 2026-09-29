# Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # New-/Set-/Remove-Mtr* functions only build in-memory objects or write the local report files;
        # nothing in the tenant is changed, so ShouldProcess adds no safety.
        'PSUseShouldProcessForStateChangingFunctions'
        # Check functions share one signature (Model, Context, Baseline, Settings) even when a check needs
        # fewer inputs, and collector parameters are consumed inside Invoke-MtrCollectorStep script blocks,
        # which the analyzer cannot follow.
        'PSReviewUnusedParameter'
        # Get-MtrIntuneData / Test-MtrGroups etc. describe collections.
        'PSUseSingularNouns'
    )
}
