<#
    Credit Card Bruteforcer by Apoorv Verma [AP]
#>
param ($Dict = ".\Hashes.txt", $PinFile = ".\Pans.txt",[Parameter(ValueFromPipeline=$TRUE)]$Hashes)
# =======================================START=OF=COMPILER==========================================================|
#    The Following Code was added by AP-Compiler Version [1.2] To Make this program independent of AP-Core Engine
#    GitHub: https://github.com/avdaredevil/AP-Compiler
# ==================================================================================================================|
$Script:PSHell=$(if($PSHell){$PSHell}elseif($PSScriptRoot){$PSScriptRoot}else{"."});
iex ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("ZnVuY3Rpb24gQVAtUmVxdWlyZSB7cGFyYW0oW1BhcmFtZXRlcihNYW5kYXRvcnk9JFRydWUpXVtBbGlhcygiRnVuY3Rpb25hbGl0eSIsIkxpYnJhcnkiKV1bU3RyaW5nXSRMaWIsIFtTY3JpcHRCbG9ja10kT25GYWlsPXt9LCBbU3dpdGNoXSRQYXNzVGhydSkNCg0KICAgIFtib29sXSRTdGF0ID0gJChzd2l0Y2ggLXJlZ2V4ICgkTGliLnRyaW0oKSkgew0KICAgICAgICAiXkludGVybmV0IiAge3Rlc3QtY29ubmVjdGlvbiBnb29nbGUuY29tIC1Db3VudCAxIC1RdWlldH0NCiAgICAgICAgIl5kZXA6KC4qKSIgIHtpZiAoJE1hdGNoZXNbMV0gLW5lICJ3aGVyZSIpe0FQLVJlcXVpcmUgImRlcDp3aGVyZSIgeyRNT0RFPTJ9fWVsc2V7JE1PREU9Mn07aWYgKCRNT0RFLTIpe0dldC1XaGVyZSAkTWF0Y2hlc1sxXX1lbHNle3RyeXsmICRNYXRjaGVzWzFdICIvZmpmZGpmZHMgLS1kc2phaGRocyAtZHNqYWRqIiAyPiRudWxsOyJzdWNjIn1jYXRjaHt9fX0NCiAgICAgICAgIl5saWI6KC4qKSIgIHskRmlsZT0kTWF0Y2hlc1sxXTskTGliPUFQLUNvbnZlcnRQYXRoICI8TElCPiI7KHRlc3QtcGF0aCAtdCBsZWFmICIkTGliXCRGaWxlIikgLW9yICh0ZXN0LXBhdGggLXQgbGVhZiAiJExpYlwkRmlsZS5kbGwiKX0NCiAgICAgICAgIl5mdW5jdGlvbjooLiopIiAge2djbSAkTWF0Y2hlc1sxXSAtZWEgU2lsZW50bHlDb250aW51ZX0NCiAgICAgICAgIl5zdHJpY3RfZnVuY3Rpb246KC4qKSIgIHtUZXN0LVBhdGggIkZ1bmN0aW9uOlwkKCRNYXRjaGVzWzFdKSJ9DQogICAgfSkNCiAgICBpZiAoISRTdGF0KSB7JE9uRmFpbC5JbnZva2UoKX0NCiAgICBpZiAoJFBhc3NUaHJ1KSB7cmV0dXJuICRTdGF0fQ0KfQoKZnVuY3Rpb24gSW52b2tlLVRlcm5hcnkge3BhcmFtKFtib29sXSRkZWNpZGVyLCBbc2NyaXB0YmxvY2tdJGlmdHJ1ZSwgW3NjcmlwdGJsb2NrXSRpZmZhbHNlKQ0KDQogICAgaWYgKCRkZWNpZGVyKSB7ICYkaWZ0cnVlfSBlbHNlIHsgJiRpZmZhbHNlIH0NCn0KCmZ1bmN0aW9uIFByb2Nlc3MtVHJhbnNwYXJlbmN5IHtwYXJhbShbQWxpYXMoIlRyYW5zcGFyZW5jeSIsIkludmlzaWJpbGl0eSIsImkiLCJ0IildW1ZhbGlkYXRlUmFuZ2UoMCwxMDApXVtpbnRdJFRyYW5zPTAsIFtQYXJhbWV0ZXIoTWFuZGF0b3J5PSRUcnVlKV0kUHJvY2VzcykNCg0KICAgIGlmICgkUHJvY2VzcyAtbWF0Y2ggIlwuZXhlJCIpIHskUHJvY2VzcyA9ICRQcm9jZXNzLnJlcGxhY2UoIi5leGUiLCIiKX0NCiAgICBUcnkgew0KICAgICAgICBpZiAoJFByb2Nlc3MubmFtZSkgeyRQcm9jID0gJFByb2Nlc3MubmFtZX0gZWxzZSB7JFByb2MgPSAoR2V0LVByb2Nlc3MgJFByb2Nlc3MgLUVycm9yQWN0aW9uIFN0b3ApWzBdLm5hbWV9DQogICAgfSBjYXRjaCB7DQogICAgICAgIGlmIChbSW50XTo6VHJ5UGFyc2UoJFByb2Nlc3MsIFtyZWZdMykpIHskUHJvYyA9ICgoR2V0LVByb2Nlc3MgfCA/IHskXy5JRCAtZXEgJFByb2Nlc3N9KVswXSkubmFtZX0NCiAgICB9DQogICAgaWYgKCRQcm9jIC1ub3RNYXRjaCAiXC5leGUkIikgeyRQcm9jID0gIiRQcm9jLmV4ZSJ9DQogICAgbmlyY21kIHdpbiB0cmFucyBwcm9jZXNzICIkUHJvYyIgKCgxMDAtJFRyYW5zKSoyNTUvMTAwKSB8IE91dC1OdWxsDQp9CgpmdW5jdGlvbiBXcml0ZS1BUCB7cGFyYW0oW1BhcmFtZXRlcihNYW5kYXRvcnk9JFRydWUpXSRUZXh0LCBbU3dpdGNoXSROb1NpZ24sIFtTd2l0Y2hdJFBsYWluVGV4dCwgW1ZhbGlkYXRlU2V0KCJDZW50ZXIiLCJSaWdodCIsIkxlZnQiKV1bU3RyaW5nXSRBbGlnbj0nTGVmdCcsIFtTd2l0Y2hdJFBhc3NUaHJ1KQ0KDQogICAgaWYgKCR0ZXh0LmNvdW50IC1ndCAxIC1vciAkdGV4dC5HZXRUeXBlKCkuTmFtZSAtbWF0Y2ggIlxbXF0kIikge3JldHVybiAkVGV4dCB8P3siJF8ifXwgJSB7V3JpdGUtQVAgJF8gLU5vU2lnbjokTm9TaWduIC1QbGFpblRleHQ6JFBsYWluVGV4dCAtQWxpZ24gJEFsaWdufX0NCiAgICBpZiAoISR0ZXh0IC1vciAkdGV4dCAtbm90bWF0Y2ggIl4oKD88Tk5MPngpfCg/PE5TPm5zPykpezAsMn0oPzx0Plw+KikoPzxzPlsrXC0hXCpcI1xAXSkoPzx3Pi4qKSIpIHtyZXR1cm4gJFRleHR9DQogICAgJHRiICA9ICIgICAgIiokTWF0Y2hlcy50Lmxlbmd0aDsNCiAgICAkQ29sID0gQHsnKyc9JzInOyctJz0nMTInOychJz0nMTQnOycqJz0nMyc7JyMnPSdEYXJrR3JheSc7J0AnPSdHcmF5J31bKCRTaWduID0gJE1hdGNoZXMuUyldDQogICAgaWYgKCEkQ29sKSB7VGhyb3cgIkluY29ycmVjdCBTaWduIFskU2lnbl0gUGFzc2VkISJ9DQogICAgJFNpZ24gPSAkKGlmICgkTm9TaWduIC1vciAkTWF0Y2hlcy5OUykgeyIifSBlbHNlIHsiWyRTaWduXSAifSkNCiAgICBBUC1SZXF1aXJlICJmdW5jdGlvbjpBbGlnbi1UZXh0IiB7ZnVuY3Rpb24gR2xvYmFsOkFsaWduLVRleHQoJGFsaWduLCR0ZXh0KSB7JHRleHR9fQ0KICAgICREYXRhID0gIiR0YiRTaWduJCgkTWF0Y2hlcy5XKSI7aWYgKCEkRGF0YSkge3JldHVybn0NCiAgICAkRGF0YSA9IEFsaWduLVRleHQgLUFsaWduICRBbGlnbiAiJHRiJFNpZ24kKCRNYXRjaGVzLlcpIg0KICAgIGlmICgkUGxhaW5UZXh0KSB7cmV0dXJuICREYXRhfQ0KICAgIFdyaXRlLUhvc3QgLU5vTmV3TGluZTokKFtib29sXSRNYXRjaGVzLk5OTCkgLWYgJENvbCAkRGF0YQ0KICAgIGlmICgkUGFzc1RocnUpIHskRGF0YX0NCn0KCmZ1bmN0aW9uIEdldC1XaGVyZSB7cGFyYW0oW1BhcmFtZXRlcihNYW5kYXRvcnk9JHRydWUpXVtzdHJpbmddJEZpbGUsIFtTd2l0Y2hdJEFsbCkNCg0KICAgIEFQLVJlcXVpcmUgImRlcDp3aGVyZSIge3Rocm93ICJOZWVkIFN5czMyXHdoZXJlIHRvIHdvcmshIjtyZXR1cm59DQogICAgJE91dCA9IHdoZXJlLmV4ZSAkZmlsZSAyPiRudWxsDQogICAgaWYgKCEkT3V0KSB7cmV0dXJufQ0KICAgIGlmICgkQWxsKSB7cmV0dXJuICRPdXR9DQogICAgcmV0dXJuIEAoJE91dClbMF0NCn0KClNldC1BbGlhcyBpbnYgUHJvY2Vzcy1UcmFuc3BhcmVuY3kKU2V0LUFsaWFzID86IEludm9rZS1UZXJuYXJ5")))
# ========================================END=OF=COMPILER===========================================================|

$TMP      = ".\AP-Cracker"
$SyncHash = [hashtable]::Synchronized(@{})
$SyncPins = [hashtable]::Synchronized(@{})
$SyncRemH = [hashtable]::Synchronized(@{})
function Card-Type($CardNumber){
    switch ("$CardNumber"[0]) { 
        0 {"ISO/TC 68 Assigned Card"}
        1 {"Airline Card"} 
        2 {"Airline Card"} 
        3 {"Diners, AMEX, or JCB Card"} 
        4 {"Visa Card"} 
        5 {"MasterCard"} 
        6 {"Retailer, Discover, or Bank Card"} 
        7 {"Petroleum Card"}
        8 {"Healthcare, Telecom, or other industry Card"} 
        9 {"National Banking Card"}
        default {"Unknown"}
    }
}
function Is-Valid-Card ([Alias("CN","Number","num")][Parameter(Mandatory=$True)]$CNumber) {
    # Based on the Luhn Check By Apoorv Verma [AP]
    $CNumber = ($CNumber+"").ToCharArray() | ? {[Char]::IsDigit("$_")} | % {[int]("$_")}
    if ($Cnumber.count -lt 4*4) {return $false}
    [Array]::Reverse($Cnumber)
    for ($i = 0;$i -lt $Cnumber.count;$i++) {
        if ($i%2 -eq 0) {continue}
        $CNumber[$i] *= 2
        while ($CNumber[$i] -gt 9) {
            $CNumber[$i] = Invoke-Expression ("$($CNumber[$i])".toCharArray() -join("+"))
        }
    }
    $Sum = 0
    $CNumber | % {$Sum += $_}
    return ($Sum%10 -eq 0)
}
function Decrypt-String($Encrypted, $Passphrase, $salt="SaltCrypto", $init="IV_Password") { 
    # If the value in the Encrypted is a string, convert it to Base64 
    if($Encrypted -is [string]){ 
        $Encrypted = [Convert]::FromBase64String($Encrypted) 
    } 
 
    # Create a COM Object for RijndaelManaged Cryptography 
    $r = new-Object System.Security.Cryptography.RijndaelManaged 
    # Convert the Passphrase to UTF8 Bytes 
    $pass = [Text.Encoding]::UTF8.GetBytes($Passphrase) 
    # Convert the Salt to UTF Bytes 
    $salt = [Text.Encoding]::UTF8.GetBytes($salt) 
 
    # Create the Encryption Key using the passphrase, salt and SHA1 algorithm at 256 bits 
    $r.Key = (new-Object Security.Cryptography.PasswordDeriveBytes $pass, $salt, "SHA1", 5).GetBytes(32) #256/8 
    # Create the Intersecting Vector Cryptology Hash with the init 
    $r.IV = (new-Object Security.Cryptography.SHA1Managed).ComputeHash( [Text.Encoding]::UTF8.GetBytes($init) )[0..15] 
    # Create a new Decryptor 
    $d = $r.CreateDecryptor() 
    # Create a New memory stream with the encrypted value. 
    $ms = new-Object IO.MemoryStream @(,$Encrypted) 
    # Read the new memory stream and read it in the cryptology stream 
    $cs = new-Object Security.Cryptography.CryptoStream $ms,$d,"Read" 
    # Read the new decrypted stream 
    $sr = new-Object IO.StreamReader $cs 
    # Return from the function the stream 
    Write-Output $sr.ReadToEnd() 
    # Stops the stream     
    $sr.Close() 
    # Stops the crypology stream 
    $cs.Close() 
    # Stops the memory stream 
    $ms.Close() 
    # Clears the RijndaelManaged Cryptology IV and Key 
    $r.Clear() 
} 
function SHA1-test-hash($toTest){
    #Hash Result
    $res=""

    #Cracked?
    $cracked=0
    
    #Hash Function
    $SHA1_hasher = new-object System.Security.Cryptography.SHA1Managed
    $toHash = [System.Text.Encoding]::UTF8.GetBytes($toTest)
    $hashByteArray = $SHA1_hasher.ComputeHash($toHash)
    foreach($byte in $hashByteArray) {
        $res += "{0:X2}" -f $byte
    }

#    write-AP "!$totest --- $res"
    #Compare and write to file
    if ($checkHash -eq $res){
        #Echo out found CC Numbers to the screen
        Write-Host "`n`nFound SHA1:"$res"`nCardNumber: "$toTest
        $toWrite="CC_Number:"+$toTest+":Hash:"+$checkHash+""
        $toWrite | out-file -encoding ASCII -append $output_file
        $cracked=1
    }
    return $res
}
#-------------------------------------------
    #[System.Text.Encoding]::ASCII.GetString(
#-------------------------------------------
[io.file]::ReadAllLines($PinFile) | ? {![String]::IsNullOrEmpty($_)} | % {
    $SyncPin += @{$_ = SHA1-test-hash $_}
}
[io.file]::ReadAllLines($Dict) | ? {![String]::IsNullOrEmpty($_)} | % {
    $str = ([System.Convert]::FromBase64String("$_"))
    $str = ($str | % {$a = [Convert]::ToString([byte]$_, 16); ?:($a.length -eq 1){"0$a"}{$a}}) -join("")
    $SyncHash += @{$str.toUpper() = -1}
}   
#seq 0000000000 1 9999999999 | % {"0"*(10-$_.length)+"$_"} | % {$SyncRemH += @{$_ = $false}}
#-------------------------------------------
$ScriptBlock = {
    Param ($Param)
    [int]$ID = $Param[0]
    $Start = $Param[1]
    $Stop = $Param[2]
    $Sync = @{}
    seq $Start 1 $Stop | % {"0"*(10-$_.length)+"$_"} | % {$Sync += @{$_ = $false}}
    $RunResult = New-Object PSObject -Property @{
        ID   = $ID
        Sync = $Sync
    }
    Return $RunResult
}
$MaxNum = 9999999999
$MaxThr = 100
$RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, 10)
$RunspacePool.Open()
$Jobs = @()
1..$MaxThr | % {
   #Start-Sleep -Seconds 1
   $StaN = ($MaxNum+1)*($_-1)/$MaxThr-1
   $EndN = ($MaxNum+1)*$_/$MaxThr-1
   if ($StaN -lt 0) {$StaN=0}
   $Job = [powershell]::Create().AddScript($ScriptBlock).AddArgument(@($_,$StaN,$EndN))
   $Job.RunspacePool = $RunspacePool
   $Jobs += New-Object PSObject -Property @{
      RunNum = $_
      Pipe = $Job
      Result = $Job.BeginInvoke()
   }
}
Do {
   Write-Host "." -NoNewline
   Start-Sleep -Seconds 1
} While ( $Jobs.Result.IsCompleted -contains $false)
Write-Host "All jobs completed!"
 
$Results = @()
ForEach ($Job in $Jobs)
{   $Results += $Job.Pipe.EndInvoke($Job.Result)
}
 
$Results 
#-------------------------------------------
if (!(test-path $TMP -type container)) {md $TMP}
Write-AP "*Finding IINs ..."
$IIN = ($SyncPin.Keys | % {$_.substring(0,6)} | sort -Unique)
Write-AP "*Running BruteForcer ..."
ForEach ($Hash in $SyncHash.Keys.GetEnumerator()) {
    
    $Hash
}
#.\CC_Checker.ps1 "$TMP\Process.txt" "$TMP\Solved.txt" 1
