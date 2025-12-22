
rule Trojan_Win32_Powdow_HC_MTB{
	meta:
		description = "Trojan:Win32/Powdow.HC!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {2e 00 65 00 78 00 65 00 20 00 2d 00 72 00 20 00 2e 00 5c 00 70 00 72 00 65 00 66 00 6c 00 69 00 67 00 68 00 74 00 2e 00 6a 00 73 00 20 00 2e 00 5c 00 61 00 70 00 70 00 2e 00 6a 00 73 00 63 00 } //1 .exe -r .\preflight.js .\app.jsc
	condition:
		((#a_00_0  & 1)*1) >=1
 
}