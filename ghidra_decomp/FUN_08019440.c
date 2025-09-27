
uint * FUN_08019440(uint *param_1,undefined4 *param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  uint uVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_080187c6(*param_2);
  uVar2 = (uint)uVar3;
  *param_1 = uVar2;
  if (uVar2 < 0x1fffffff) {
    iVar1 = uVar2 << 2;
  }
  else {
    iVar1 = -1;
  }
  uVar2 = thunk_FUN_08008466(iVar1);
  param_1[1] = uVar2;
  FUN_0800ad50((int)((ulonglong)uVar3 >> 0x20),uVar2,*param_1,0,param_4);
  return param_1;
}

