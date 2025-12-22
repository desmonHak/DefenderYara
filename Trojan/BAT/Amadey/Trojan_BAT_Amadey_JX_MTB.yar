
rule Trojan_BAT_Amadey_JX_MTB{
	meta:
		description = "Trojan:BAT/Amadey.JX!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 68 61 6e 74 6f 6d 35 33 20 53 74 65 61 6c 74 68 20 49 6e 73 74 61 6c 6c 65 72 } //1 Phantom53 Stealth Installer
		$a_01_1 = {43 6c 65 61 6e 75 70 20 74 72 61 63 65 73 } //1 Cleanup traces
		$a_01_2 = {46 75 6c 6c 20 73 69 6c 65 6e 74 20 6d 6f 64 65 20 2d 20 6e 6f 20 63 6f 6e 73 6f 6c 65 2c 20 6e 6f 20 6f 75 74 70 75 74 2c 20 6e 6f 20 74 72 61 63 65 73 } //1 Full silent mode - no console, no output, no traces
		$a_01_3 = {52 65 6d 6f 76 65 2d 49 74 65 6d 20 2d 50 61 74 68 20 24 76 62 73 50 61 74 68 20 2d 46 6f 72 63 65 20 2d 45 72 72 6f 72 41 63 74 69 6f 6e 20 53 69 6c 65 6e 74 6c 79 43 6f 6e 74 69 6e 75 65 } //1 Remove-Item -Path $vbsPath -Force -ErrorAction SilentlyContinue
		$a_01_4 = {43 6c 65 61 72 2d 48 69 73 74 6f 72 79 20 2d 45 72 72 6f 72 41 63 74 69 6f 6e 20 53 69 6c 65 6e 74 6c 79 43 6f 6e 74 69 6e 75 65 } //1 Clear-History -ErrorAction SilentlyContinue
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}