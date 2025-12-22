
rule TrojanDownloader_O97M_Matanbuchus_PA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Matanbuchus.PA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 49 6e 73 74 61 6c 6c 50 72 6f 64 75 63 74 } //1 .InstallProduct
		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 69 6e 64 6f 77 73 49 6e 73 74 61 6c 6c 65 72 2e 49 6e 73 74 61 6c 6c 65 72 22 29 } //1 = CreateObject("WindowsInstaller.Installer")
		$a_01_2 = {62 61 6e 6b 72 75 70 74 63 79 2d 64 69 76 6f 72 63 65 2e 63 6f 6d 2f 42 61 6e 6b 72 75 70 74 63 79 2f 64 62 2e 70 61 6b } //3 bankruptcy-divorce.com/Bankruptcy/db.pak
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3) >=5
 
}