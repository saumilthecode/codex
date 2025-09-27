
void FUN_08010654(int param_1,undefined4 param_2)

{
  undefined4 uVar1;
  
  uVar1 = FUN_08018e74(param_2);
  *(undefined4 *)(param_1 + 0x80) = uVar1;
  uVar1 = FUN_08018988(param_2);
  *(undefined4 *)(param_1 + 0x84) = uVar1;
  uVar1 = FUN_08018970(param_2);
  *(undefined4 *)(param_1 + 0x88) = uVar1;
  return;
}

