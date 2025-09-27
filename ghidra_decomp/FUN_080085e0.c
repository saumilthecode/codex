
void FUN_080085e0(int *param_1,undefined4 param_2)

{
  int iVar1;
  
  FUN_080106a8(param_1 + 1);
  param_1[0x1f] = 0;
  param_1[0x20] = 0;
  param_1[0x21] = 0;
  param_1[0x22] = 0;
  param_1[0x1d] = 0;
  *(undefined2 *)(param_1 + 0x1e) = 0;
  iVar1 = DAT_08008614;
  *param_1 = DAT_08008614;
  param_1[1] = iVar1 + 0x14;
  FUN_080105fe(param_1 + 1,param_2);
  return;
}

