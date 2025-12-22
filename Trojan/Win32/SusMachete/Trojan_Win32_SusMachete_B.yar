
rule Trojan_Win32_SusMachete_B{
	meta:
		description = "Trojan:Win32/SusMachete.B,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 63 64 20 } //cmd.exe /c cd   1
		$a_80_1 = {67 65 6f 69 70 2e 65 78 65 } //geoip.exe  1
		$a_00_2 = {20 00 26 00 26 00 20 00 } //1  && 
		$a_80_3 = {5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 43 68 72 6f 6d 65 5c 47 6f 6f 67 6c 65 } //\AppData\Roaming\Chrome\Google  1
		$a_80_4 = {3e 20 67 65 6f 69 70 2e 74 78 74 } //> geoip.txt  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_00_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}