
void FUN_08018918(undefined4 *param_1)

{
  uint uVar1;
  undefined8 uVar2;
  
  uVar2 = FUN_08018910(*param_1);
  uVar1 = (uint)((ulonglong)uVar2 >> 0x20);
  if ((uint)uVar2 < uVar1) {
    FUN_08010508(DAT_08018948,DAT_0801894c,uVar1,(uint)uVar2);
  }
  FUN_0800a844(param_1);
  return;
}

