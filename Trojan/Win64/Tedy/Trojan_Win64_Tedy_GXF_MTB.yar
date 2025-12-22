
rule Trojan_Win64_Tedy_GXF_MTB{
	meta:
		description = "Trojan:Win64/Tedy.GXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {f3 0f 6f 00 48 83 c0 10 66 0f 6f c8 66 0f fc c0 66 0f 71 d1 05 66 0f fc c0 66 0f db ca 66 0f fc c0 66 0f eb c1 0f 11 40 f0 49 39 c0 } //5
		$a_01_1 = {48 89 c8 66 41 0f 6e c9 66 0f 70 c9 00 f3 0f 6f 00 48 83 c0 10 66 0f fc c1 0f 11 40 f0 49 39 c0 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}