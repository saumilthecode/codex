
undefined8 FUN_08024b30(undefined4 param_1,int param_2,int param_3)

{
  int iVar1;
  undefined8 uVar2;
  
  uVar2 = FUN_0802965c();
  if ((param_3 != 0) && (iVar1 = 0x6b - ((uint)(param_2 << 1) >> 0x15), 0 < iVar1)) {
    uVar2 = FUN_08006228((int)uVar2,(int)((ulonglong)uVar2 >> 0x20),0,iVar1 * 0x100000 + 0x3ff00000)
    ;
  }
  return uVar2;
}

