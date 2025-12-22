
rule Trojan_Win32_HijackExecFlowCorProfiler_A_sms{
	meta:
		description = "Trojan:Win32/HijackExecFlowCorProfiler.A!sms,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 4f 52 5f 45 4e 41 42 4c 45 5f 50 52 4f 46 49 4c 49 4e 47 3d 31 } //1 COR_ENABLE_PROFILING=1
		$a_01_1 = {43 4f 52 5f 50 52 4f 46 49 4c 45 52 3d 7b 31 32 33 34 35 36 37 38 2d 31 32 33 34 2d 31 32 33 34 2d 31 32 33 34 2d 31 32 33 34 35 36 37 38 39 31 32 33 7d } //1 COR_PROFILER={12345678-1234-1234-1234-123456789123}
		$a_01_2 = {43 4f 52 5f 50 52 4f 46 49 4c 45 52 5f 50 41 54 48 3d } //1 COR_PROFILER_PATH=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}