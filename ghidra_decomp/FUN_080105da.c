
void FUN_080105da(int param_1,undefined4 param_2)

{
  undefined4 uVar1;
  
  uVar1 = FUN_08011254(param_2);
  *(undefined4 *)(param_1 + 0x7c) = uVar1;
  uVar1 = FUN_08010d3c(param_2);
  *(undefined4 *)(param_1 + 0x80) = uVar1;
  uVar1 = FUN_08010d24(param_2);
  *(undefined4 *)(param_1 + 0x84) = uVar1;
  return;
}

