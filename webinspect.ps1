#Written for Powershell 7 
#Variables
$wiAPIurl = '13.73.96.195:8083'
$sscURL = 'http://13.70.155.45:8080/ssc/'
$applicationVersionID = '6'
$sscToken = '6d8b3b1c-e6a3-4bb0-b2eb-bc61976c0bb8'

$scanURL = 'http://zero.webappsecurity.com/'
$crawlAuditMode = 'CrawlandAudit'
$scanName = 'DastWebInspectSecurity'

#API Auth
#$pwd = ConvertTo-SecureString "password1" -AsPlainText -Force
#$cred = New-Object Management.Automation.PSCredential ('username1', $pwd)

#1. Run the scan
$body = '{
"settingsName": "Default",
"overrides": {
"scanName": "' + $scanName + '",
"startUrls": [
"' + $scanURL + '"
],
"crawlAuditMode": "' + $crawlAuditMode + '",
"startOption": "Url"
}'

$responseurl = 'http://' + $wiAPIurl + '/webinspect/scanner/scans'
echo $responseurl
$response = Invoke-RestMethod -Method POST -ContentType "application/json" -Body $body -uri $responseurl

#Store unique ScanId
$scanId = $response.ScanId
Write-Host -ForegroundColor Green ("Scan started succesfully with Scan Id: " + $scanId)
#2. Get the current Status of the Scan
$StatusUrl = 'http://' + $wiAPIurl + '/webinspect/scanner/scans/' + $scanId + '/log'
$ScanCompleted = "ScanCompleted"
$ScanStopped = "ScanStopped"
$ScanInterrupted = "ScanInterrupted"
 
#Wait until the ScanStatus changed to ScanCompleted, ScanStopped or ScanInterrupted
do{
    $status = Invoke-RestMethod -Method GET -ContentType "application/json" -uri "$StatusUrl"
    $ScanDate =  $status[$status.Length-1].Date
    $ScanMessage = $status[$status.Length-1].Message
    $ScanStatus =  $status[$status.Length-1].Type
    Write-Host ($ScanDate, $ScanMessage, $ScanStatus) -Separator " - "
    Start-Sleep -Seconds 20
}
while(($ScanStatus -ne $ScanCompleted) -and ($ScanStatus -ne $ScanStopped) -and ($ScanStatus -ne $ScanInterrupted))
 
if ($ScanStatus -eq $ScanCompleted){
    Write-Host -ForegroundColor Green ("Scan completed!") `n

    #3. Export the scan to the FPR format
    $fprurl = 'http://' + $wiAPIurl + '/webinspect/scanner/scans/' + $scanId + '.fpr '
    $path = $scanId + '.fpr'
    echo $fprurl

    Write-Host ("Downloading the result file (fpr)...")
    Invoke-RestMethod -Method GET -OutFile $path -uri "$fprurl"
    Write-Host -ForegroundColor Green ("Result file (fpr) download done!") `n

    #4. Upload the Results to SSC
    $sscheaders = '@{
        "Authorization" = "FortifyToken '+ $sscToken + '"
        "ContentType" = "multipart/form-data"
        "accept" = "application/json"
    }'
    $sscheader_exp = Invoke-Expression $sscheaders
    $sscuploadurl = $sscURL + 'api/v1/projectVersions/' + $applicationVersionID + '/artifacts'

    Write-Host ("Starting Upload to SSC...")
    fortifyclient.bat uploadFPR -url http://13.70.155.45:8080/ssc -authtoken $sscToken -f $path -application test-wi -applicationVersion 2.0
    #Invoke-RestMethod -uri $sscuploadurl -Method POST -Headers $sscheader_exp -Body @{file=(Get-Item $path)}
    Write-Host -ForegroundColor Green ("Finished! Scan Results are now availible in the Software Security Center!")
} else {
    Write-Host -ForegroundColor Red ("Error occured after Scan was finished!")
}