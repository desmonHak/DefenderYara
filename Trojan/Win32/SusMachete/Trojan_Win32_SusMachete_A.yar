
rule Trojan_Win32_SusMachete_A{
	meta:
		description = "Trojan:Win32/SusMachete.A,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {73 63 68 74 61 73 6b 73 2e 65 78 65 20 2f 63 72 65 61 74 65 20 2f 53 54 20 } //schtasks.exe /create /ST   1
		$a_80_1 = {20 2f 53 43 20 4d 49 4e 55 54 45 20 2f 4d 4f 20 } // /SC MINUTE /MO   1
		$a_80_2 = {20 2f 54 4e 20 } // /TN   1
		$a_80_3 = {5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 43 68 72 6f 6d 65 5c 47 6f 6f 67 6c 65 } //\AppData\Roaming\Chrome\Google  1
		$a_80_4 = {20 2f 54 52 20 } // /TR   1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}