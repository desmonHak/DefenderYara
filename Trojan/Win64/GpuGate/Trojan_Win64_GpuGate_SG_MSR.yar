
rule Trojan_Win64_GpuGate_SG_MSR{
	meta:
		description = "Trojan:Win64/GpuGate.SG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 "
		
	strings :
		$a_80_0 = {5f 5f 6b 65 72 6e 65 6c 20 76 6f 69 64 20 73 74 72 65 61 6d 5f 64 65 63 72 79 70 74 28 } //__kernel void stream_decrypt(  1
		$a_80_1 = {75 69 6e 74 20 78 20 3d 20 73 65 65 64 20 2b 20 69 20 2a 20 31 36 36 34 35 32 35 20 2b 20 31 30 31 33 39 30 34 32 32 33 } //uint x = seed + i * 1664525 + 1013904223  1
		$a_80_2 = {75 63 68 61 72 20 6b 20 3d 20 28 78 20 3e 3e 20 38 29 20 26 20 30 78 46 46 } //uchar k = (x >> 8) & 0xFF  1
		$a_80_3 = {64 73 74 5b 69 5d 20 3d 20 28 73 72 63 5b 69 5d 20 2d 20 6b 29 20 26 20 30 78 46 46 } //dst[i] = (src[i] - k) & 0xFF  1
		$a_80_4 = {4f 70 65 6e 43 4c 2e 64 6c 6c } //OpenCL.dll  1
		$a_80_5 = {72 65 73 2e 7a 69 70 } //res.zip  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=5
 
}