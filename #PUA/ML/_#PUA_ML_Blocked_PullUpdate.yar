
rule _#PUA_ML_Blocked_PullUpdate{
	meta:
		description = "!#PUA:ML:Blocked:PullUpdate,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {31 36 33 39 33 32 3a 31 3a 30 3a 34 2e 31 31 2e 30 2e 34 39 31 34 35 } //1 163932:1:0:4.11.0.49145
		$a_01_1 = {70 00 72 00 6f 00 6d 00 70 00 74 00 2e 00 65 00 78 00 65 00 } //1 prompt.exe
		$a_01_2 = {53 00 6d 00 61 00 72 00 74 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 } //1 SmartAssembly
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}