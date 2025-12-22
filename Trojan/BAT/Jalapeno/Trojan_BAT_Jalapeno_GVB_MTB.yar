
rule Trojan_BAT_Jalapeno_GVB_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.GVB!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {3a 00 2f 00 2f 00 66 00 75 00 63 00 6b 00 79 00 6f 00 75 00 2e 00 63 00 6f 00 6d 00 2f 00 3f 00 68 00 65 00 63 00 6b 00 65 00 72 00 } //2 ://fuckyou.com/?hecker
		$a_01_1 = {43 00 72 00 65 00 61 00 74 00 65 00 64 00 20 00 6d 00 75 00 74 00 61 00 74 00 65 00 64 00 20 00 63 00 6f 00 70 00 79 00 } //1 Created mutated copy
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}