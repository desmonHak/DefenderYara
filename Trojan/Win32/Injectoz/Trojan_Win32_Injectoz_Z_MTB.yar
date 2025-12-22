
rule Trojan_Win32_Injectoz_Z_MTB{
	meta:
		description = "Trojan:Win32/Injectoz.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 79 04 83 c6 04 83 ea 04 83 c0 10 83 e9 10 3b f2 7c c4 5d ba 01 00 00 00 39 93 f0 00 00 00 0f 8e b6 01 00 00 8d 43 02 8b 48 0e 0f b6 78 0f 8b 3c bd 18 75 40 00 83 c0 10 8b f1 c1 ee 18 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}