
void FUN_0800c1b8(undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined1 uVar1;
  undefined4 uVar2;
  undefined1 auStack_28 [28];
  
  uVar1 = FUN_08022634(param_2);
  *(undefined1 *)(param_3 + 0x24) = uVar1;
  uVar1 = FUN_0802263a(param_2);
  *(undefined4 *)(param_3 + 8) = 0;
  *(undefined4 *)(param_3 + 0x14) = 0;
  *(undefined4 *)(param_3 + 0x1c) = 0;
  *(undefined1 *)(param_3 + 100) = 1;
  *(undefined1 *)(param_3 + 0x25) = uVar1;
  FUN_08022640(auStack_28,param_2);
  uVar2 = FUN_0800b742(param_3 + 8,auStack_28);
  *(undefined4 *)(param_3 + 0xc) = uVar2;
  FUN_08006cec(auStack_28);
  FUN_0802264e(auStack_28,param_2);
  uVar2 = FUN_0800b742(param_3 + 0x14,auStack_28);
  *(undefined4 *)(param_3 + 0x18) = uVar2;
  FUN_08006cec(auStack_28);
  FUN_0802265c(auStack_28,param_2);
  uVar2 = FUN_0800b742(param_3 + 0x1c,auStack_28);
  *(undefined4 *)(param_3 + 0x20) = uVar2;
  FUN_08006cec(auStack_28);
  return;
}

