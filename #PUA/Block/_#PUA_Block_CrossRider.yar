
rule _#PUA_Block_CrossRider{
	meta:
		description = "!#PUA:Block:CrossRider,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {47 6c 6f 62 61 6c 5c 6d 79 73 65 6c 66 4c 6f 67 4d 75 74 65 78 } //Global\myselfLogMutex  2
		$a_00_1 = {43 72 6f 73 73 72 69 64 65 72 41 70 70 } //1 CrossriderApp
		$a_01_2 = {2e 3f 41 56 43 43 72 6f 73 73 52 69 64 65 72 4c 6f 67 55 73 65 72 40 40 } //1 .?AVCCrossRiderLogUser@@
	condition:
		((#a_80_0  & 1)*2+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule _#PUA_Block_CrossRider_2{
	meta:
		description = "!#PUA:Block:CrossRider,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {47 6c 6f 62 61 6c 5c 6d 79 61 70 70 4c 6f 67 4d 75 74 65 78 } //Global\myappLogMutex  2
		$a_00_1 = {41 64 64 43 72 6f 73 73 52 69 64 65 72 53 65 61 72 63 68 50 72 6f 76 69 64 65 72 } //1 AddCrossRiderSearchProvider
		$a_00_2 = {41 56 43 43 72 6f 73 73 52 69 64 65 72 4c 6f 67 67 65 72 } //1 AVCCrossRiderLogger
		$a_80_3 = {43 72 6f 73 73 72 69 64 65 72 } //Crossrider  1
	condition:
		((#a_80_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_80_3  & 1)*1) >=3
 
}
rule _#PUA_Block_CrossRider_3{
	meta:
		description = "!#PUA:Block:CrossRider,SIGNATURE_TYPE_PEHSTR,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 6c 6f 62 61 6c 5c 6d 79 61 70 70 4c 6f 67 4d 75 74 65 78 } //2 Global\myappLogMutex
		$a_01_1 = {43 72 6f 73 73 72 69 64 65 72 42 61 63 6b 67 72 6f 75 6e 64 } //2 CrossriderBackground
		$a_01_2 = {41 56 43 43 72 6f 73 73 52 69 64 65 72 4c 6f 67 55 73 65 72 } //2 AVCCrossRiderLogUser
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}