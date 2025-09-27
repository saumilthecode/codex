
void FUN_0800c234(undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  undefined1 auStack_28 [28];
  
  uVar1 = FUN_0800dee6(param_2);
  *(undefined4 *)(param_3 + 0x24) = uVar1;
  uVar1 = FUN_0800deec(param_2);
  *(undefined4 *)(param_3 + 8) = 0;
  *(undefined4 *)(param_3 + 0x14) = 0;
  *(undefined4 *)(param_3 + 0x1c) = 0;
  *(undefined1 *)(param_3 + 0x124) = 1;
  *(undefined4 *)(param_3 + 0x28) = uVar1;
  FUN_0800def2(auStack_28,param_2);
  uVar1 = FUN_0800b742(param_3 + 8,auStack_28);
  *(undefined4 *)(param_3 + 0xc) = uVar1;
  FUN_08006cec(auStack_28);
  FUN_0800df00(auStack_28,param_2);
  uVar1 = FUN_0800b768(param_3 + 0x14,auStack_28);
  *(undefined4 *)(param_3 + 0x18) = uVar1;
  FUN_0801e9cc(auStack_28);
  FUN_0800df0e(auStack_28,param_2);
  uVar1 = FUN_0800b768(param_3 + 0x1c,auStack_28);
  *(undefined4 *)(param_3 + 0x20) = uVar1;
  FUN_0801e9cc(auStack_28);
  return;
}

