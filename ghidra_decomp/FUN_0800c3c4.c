
void FUN_0800c3c4(undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined1 uVar1;
  undefined4 uVar2;
  undefined1 auStack_28 [28];
  
  uVar1 = FUN_08022578(param_2);
  *(undefined1 *)(param_3 + 0x11) = uVar1;
  uVar1 = FUN_0802257e(param_2);
  *(undefined1 *)(param_3 + 0x12) = uVar1;
  uVar2 = FUN_080225bc(param_2);
  *(undefined4 *)(param_3 + 8) = 0;
  *(undefined4 *)(param_3 + 0x14) = 0;
  *(undefined4 *)(param_3 + 0x1c) = 0;
  *(undefined4 *)(param_3 + 0x24) = 0;
  *(undefined1 *)(param_3 + 0x43) = 1;
  *(undefined4 *)(param_3 + 0x2c) = uVar2;
  FUN_08022584(auStack_28,param_2);
  uVar2 = FUN_0800b742(param_3 + 8,auStack_28);
  *(undefined4 *)(param_3 + 0xc) = uVar2;
  FUN_08006cec(auStack_28);
  FUN_08022592(auStack_28,param_2);
  uVar2 = FUN_0800b742(param_3 + 0x14,auStack_28);
  *(undefined4 *)(param_3 + 0x18) = uVar2;
  FUN_08006cec(auStack_28);
  FUN_080225a0(auStack_28,param_2);
  uVar2 = FUN_0800b742(param_3 + 0x1c,auStack_28);
  *(undefined4 *)(param_3 + 0x20) = uVar2;
  FUN_08006cec(auStack_28);
  FUN_080225ae(auStack_28,param_2);
  uVar2 = FUN_0800b742(param_3 + 0x24,auStack_28);
  *(undefined4 *)(param_3 + 0x28) = uVar2;
  FUN_08006cec(auStack_28);
  uVar2 = FUN_080225c2(param_2);
  *(undefined4 *)(param_3 + 0x30) = uVar2;
  uVar2 = FUN_080225cc(param_2);
  *(undefined4 *)(param_3 + 0x34) = uVar2;
  return;
}

