
void FUN_0800c51c(undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  undefined1 auStack_28 [28];
  
  uVar1 = FUN_0800de2a(param_2);
  *(undefined4 *)(param_3 + 0x14) = uVar1;
  uVar1 = FUN_0800de30(param_2);
  *(undefined4 *)(param_3 + 0x18) = uVar1;
  uVar1 = FUN_0800de6e(param_2);
  *(undefined4 *)(param_3 + 8) = 0;
  *(undefined4 *)(param_3 + 0x1c) = 0;
  *(undefined4 *)(param_3 + 0x24) = 0;
  *(undefined4 *)(param_3 + 0x2c) = 0;
  *(undefined1 *)(param_3 + 0x6c) = 1;
  *(undefined4 *)(param_3 + 0x34) = uVar1;
  FUN_0800de36(auStack_28,param_2);
  uVar1 = FUN_0800b742(param_3 + 8,auStack_28);
  *(undefined4 *)(param_3 + 0xc) = uVar1;
  FUN_08006cec(auStack_28);
  FUN_0800de44(auStack_28,param_2);
  uVar1 = FUN_0800b768(param_3 + 0x1c,auStack_28);
  *(undefined4 *)(param_3 + 0x20) = uVar1;
  FUN_0801e9cc(auStack_28);
  FUN_0800de52(auStack_28,param_2);
  uVar1 = FUN_0800b768(param_3 + 0x24,auStack_28);
  *(undefined4 *)(param_3 + 0x28) = uVar1;
  FUN_0801e9cc(auStack_28);
  FUN_0800de60(auStack_28,param_2);
  uVar1 = FUN_0800b768(param_3 + 0x2c,auStack_28);
  *(undefined4 *)(param_3 + 0x30) = uVar1;
  FUN_0801e9cc(auStack_28);
  uVar1 = FUN_0800de74(param_2);
  *(undefined4 *)(param_3 + 0x38) = uVar1;
  uVar1 = FUN_0800de7e(param_2);
  *(undefined4 *)(param_3 + 0x3c) = uVar1;
  return;
}

