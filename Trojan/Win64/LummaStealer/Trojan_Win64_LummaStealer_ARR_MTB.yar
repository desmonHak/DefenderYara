
rule Trojan_Win64_LummaStealer_ARR_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 03 00 00 "
		
	strings :
		$a_03_0 = {f3 41 0f 6f 02 49 83 c2 ?? 66 0f fc c1 41 0f 11 42 f0 49 39 c2 75 } //50
		$a_03_1 = {f3 0f 6f 0a 48 83 c2 ?? 66 0f 6f c1 66 0f 71 f0 } //20
		$a_03_2 = {41 f6 20 49 83 c0 ?? 41 88 40 ff 49 39 c8 75 } //30
	condition:
		((#a_03_0  & 1)*50+(#a_03_1  & 1)*20+(#a_03_2  & 1)*30) >=50
 
}