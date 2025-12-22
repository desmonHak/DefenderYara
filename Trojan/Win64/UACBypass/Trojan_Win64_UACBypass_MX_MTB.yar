
rule Trojan_Win64_UACBypass_MX_MTB{
	meta:
		description = "Trojan:Win64/UACBypass.MX!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 72 69 76 65 72 49 6e 73 74 61 6c 6c 5c 62 69 6e 5c 54 61 73 6b 53 63 68 65 64 75 6c 65 72 5f 78 36 34 2e 70 64 62 } //1 DriverInstall\bin\TaskScheduler_x64.pdb
		$a_01_1 = {62 69 6e 5c 42 79 70 61 73 73 55 41 43 44 6c 6c 5f 78 38 36 2e 70 64 62 } //1 bin\BypassUACDll_x86.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}