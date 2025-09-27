
uint FUN_080262b4(int param_1,undefined4 *param_2)

{
  int iVar1;
  uint uVar2;
  byte *pbVar3;
  
  if ((param_1 != 0) && (*(int *)(param_1 + 0x20) == 0)) {
    FUN_08025ec4();
  }
  iVar1 = FUN_080261d0(param_1,param_2);
  if (iVar1 == 0) {
    param_2[1] = param_2[1] + -1;
    pbVar3 = (byte *)*param_2;
    *param_2 = pbVar3 + 1;
    uVar2 = (uint)*pbVar3;
  }
  else {
    uVar2 = 0xffffffff;
  }
  return uVar2;
}

