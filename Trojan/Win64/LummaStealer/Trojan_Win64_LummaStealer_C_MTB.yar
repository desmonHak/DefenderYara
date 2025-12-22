
rule Trojan_Win64_LummaStealer_C_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 0f af fe 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 48 f7 ef 48 c1 fa ?? 49 89 f8 48 c1 ff ?? 48 29 fa 48 6b d2 ?? 49 29 d0 4a 8d 0c 06 e9 } //3
		$a_01_1 = {48 85 c9 48 0f 4c ca 48 ff c1 48 89 d8 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}