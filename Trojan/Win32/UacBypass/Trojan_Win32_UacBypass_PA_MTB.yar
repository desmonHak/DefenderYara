
rule Trojan_Win32_UacBypass_PA_MTB{
	meta:
		description = "Trojan:Win32/UacBypass.PA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {72 00 65 00 67 00 20 00 61 00 64 00 64 00 } //2 reg add
		$a_00_1 = {48 00 4b 00 43 00 55 00 5c 00 45 00 6e 00 76 00 69 00 72 00 6f 00 6e 00 6d 00 65 00 6e 00 74 00 } //1 HKCU\Environment
		$a_00_2 = {2f 00 76 00 20 00 77 00 69 00 6e 00 64 00 69 00 72 00 20 00 2f 00 74 00 20 00 52 00 45 00 47 00 5f 00 53 00 5a 00 20 00 2f 00 64 00 } //1 /v windir /t REG_SZ /d
		$a_00_3 = {2f 00 66 00 } //1 /f
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}