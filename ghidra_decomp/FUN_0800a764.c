
/* WARNING: Control flow encountered bad instruction data */

void FUN_0800a764(uint param_1,undefined4 param_2)

{
  int iVar1;
  uint uVar2;
  undefined8 uVar3;
  
  uVar3 = CONCAT44(param_2,param_1);
  if (DAT_0800a7bc < param_1) {
    uVar3 = FUN_08010502(DAT_0800a7c0);
  }
  uVar2 = (uint)((ulonglong)uVar3 >> 0x20);
  if ((uVar2 < (uint)uVar3) && ((uint)uVar3 < uVar2 << 1)) {
    param_1 = uVar2 << 1;
  }
  iVar1 = param_1 + 0xd;
  if ((param_1 + 0x1d < 0x1001) || (param_1 <= uVar2)) {
    if (iVar1 < 0) {
      FUN_080104ea();
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
  }
  else {
    param_1 = (param_1 + 0x1000) - (param_1 + 0x1d & 0xfff);
    if (DAT_0800a7bc <= param_1) {
      param_1 = DAT_0800a7bc;
    }
    iVar1 = param_1 + 0xd;
  }
  iVar1 = FUN_08008466(iVar1);
  *(uint *)(iVar1 + 4) = param_1;
  *(undefined4 *)(iVar1 + 8) = 0;
  return;
}

