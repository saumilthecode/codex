
void FUN_080098ec(undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined1 uVar1;
  undefined4 uVar2;
  undefined4 local_14;
  int iStack_10;
  
  local_14 = param_2;
  iStack_10 = param_3;
  uVar1 = FUN_08010ec8(param_2);
  *(undefined1 *)(param_3 + 0x11) = uVar1;
  uVar1 = FUN_08010ece(param_2);
  *(undefined1 *)(param_3 + 0x12) = uVar1;
  uVar2 = FUN_08010f0c(param_2);
  *(undefined4 *)(param_3 + 8) = 0;
  *(undefined4 *)(param_3 + 0x14) = 0;
  *(undefined4 *)(param_3 + 0x1c) = 0;
  *(undefined4 *)(param_3 + 0x24) = 0;
  *(undefined1 *)(param_3 + 0x43) = 1;
  *(undefined4 *)(param_3 + 0x2c) = uVar2;
  FUN_08010ed4(&local_14,param_2);
  uVar2 = FUN_080091d0(param_3 + 8,&local_14);
  *(undefined4 *)(param_3 + 0xc) = uVar2;
  FUN_080091fc(local_14);
  FUN_08010ee2(&local_14,param_2);
  uVar2 = FUN_080091d0(param_3 + 0x14,&local_14);
  *(undefined4 *)(param_3 + 0x18) = uVar2;
  FUN_080091fc(local_14);
  FUN_08010ef0(&local_14,param_2);
  uVar2 = FUN_080091d0(param_3 + 0x1c,&local_14);
  *(undefined4 *)(param_3 + 0x20) = uVar2;
  FUN_080091fc(local_14);
  FUN_08010efe(&local_14,param_2);
  uVar2 = FUN_080091d0(param_3 + 0x24,&local_14);
  *(undefined4 *)(param_3 + 0x28) = uVar2;
  FUN_080091fc(local_14);
  uVar2 = FUN_08010f12(param_2);
  *(undefined4 *)(param_3 + 0x30) = uVar2;
  uVar2 = FUN_08010f1c(param_2);
  *(undefined4 *)(param_3 + 0x34) = uVar2;
  return;
}

