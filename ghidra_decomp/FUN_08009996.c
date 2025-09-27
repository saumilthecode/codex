
void FUN_08009996(undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  undefined4 local_14;
  int iStack_10;
  
  local_14 = param_2;
  iStack_10 = param_3;
  uVar1 = FUN_08018b42(param_2);
  *(undefined4 *)(param_3 + 0x14) = uVar1;
  uVar1 = FUN_08018b48(param_2);
  *(undefined4 *)(param_3 + 0x18) = uVar1;
  uVar1 = FUN_08018b86(param_2);
  *(undefined4 *)(param_3 + 8) = 0;
  *(undefined4 *)(param_3 + 0x1c) = 0;
  *(undefined4 *)(param_3 + 0x24) = 0;
  *(undefined4 *)(param_3 + 0x2c) = 0;
  *(undefined1 *)(param_3 + 0x6c) = 1;
  *(undefined4 *)(param_3 + 0x34) = uVar1;
  FUN_08018b4e(&local_14,param_2);
  uVar1 = FUN_080091d0(param_3 + 8,&local_14);
  *(undefined4 *)(param_3 + 0xc) = uVar1;
  FUN_080091fc(local_14);
  FUN_08018b5c(&local_14,param_2);
  uVar1 = FUN_08009254(param_3 + 0x1c,&local_14);
  *(undefined4 *)(param_3 + 0x20) = uVar1;
  FUN_08009134(local_14);
  FUN_08018b6a(&local_14,param_2);
  uVar1 = FUN_08009254(param_3 + 0x24,&local_14);
  *(undefined4 *)(param_3 + 0x28) = uVar1;
  FUN_08009134(local_14);
  FUN_08018b78(&local_14,param_2);
  uVar1 = FUN_08009254(param_3 + 0x2c,&local_14);
  *(undefined4 *)(param_3 + 0x30) = uVar1;
  FUN_08009134(local_14);
  uVar1 = FUN_08018b8c(param_2);
  *(undefined4 *)(param_3 + 0x38) = uVar1;
  uVar1 = FUN_08018b96(param_2);
  *(undefined4 *)(param_3 + 0x3c) = uVar1;
  return;
}

