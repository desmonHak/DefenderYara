
rule Trojan_Win64_BypassUAC_SX_MTB{
	meta:
		description = "Trojan:Win64/BypassUAC.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {62 6f 74 6b 69 6c 6c 65 72 } //botkiller  1
		$a_80_1 = {64 65 6c 20 2f 66 20 2f 73 20 2f 71 } //del /f /s /q  1
		$a_80_2 = {73 68 75 74 64 6f 77 6e 20 2f 72 20 2f 66 } //shutdown /r /f  1
		$a_80_3 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 } //vssadmin delete shadows  1
		$a_80_4 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 22 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 55 70 64 61 74 65 4f 72 63 68 65 73 74 72 61 74 6f 72 5c 53 65 63 75 72 69 74 79 55 70 64 61 74 65 22 20 2f 74 72 20 22 } //schtasks /create /tn "Microsoft\Windows\UpdateOrchestrator\SecurityUpdate" /tr "  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}