
rule Trojan_Win64_LummaStealer_HEO_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.HEO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 8d 40 01 41 80 30 32 48 39 c8 74 1f } //1
		$a_01_1 = {80 30 32 80 70 01 32 48 83 c0 02 48 39 c8 75 f0 } //1
		$a_03_2 = {f6 22 88 02 ?? ?? ?? 48 83 c2 ?? 48 39 ca 75 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}