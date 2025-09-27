
uint FUN_08010c20(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  uint uVar1;
  undefined8 uVar2;
  
  uVar2 = FUN_08010c1a();
  uVar1 = (uint)((ulonglong)uVar2 >> 0x20);
  if ((uint)uVar2 < uVar1) {
    FUN_08010508(DAT_08010c3c,param_3,uVar1,(uint)uVar2);
  }
  return uVar1;
}

