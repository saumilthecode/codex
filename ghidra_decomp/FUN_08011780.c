
void FUN_08011780(int param_1,undefined4 param_2)

{
  undefined1 uVar1;
  undefined4 uVar2;
  int iVar3;
  char *pcVar4;
  undefined4 uVar5;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  
  uVar2 = FUN_080113fc(param_2);
  FUN_08010ee2(&local_20,uVar2);
  FUN_0801175c(&local_30,&local_20);
  FUN_08010c74(local_20);
  FUN_08010ef0(&local_20,uVar2);
  FUN_0801175c(&local_28,&local_20);
  FUN_08010c74(local_20);
  FUN_08010efe(&local_34,uVar2);
  FUN_0801175c(&local_20,&local_34);
  FUN_08010c74(local_34);
  FUN_08010ed4(&local_34,uVar2);
  iVar3 = FUN_08010c1a(local_34);
  pcVar4 = (char *)thunk_FUN_08008466();
  FUN_0800a6c0(&local_34,pcVar4,iVar3,0);
  *(char **)(param_1 + 8) = pcVar4;
  *(int *)(param_1 + 0xc) = iVar3;
  if (iVar3 != 0) {
    if (*pcVar4 < '\x01') {
      iVar3 = 0;
    }
    else {
      iVar3 = 1;
    }
  }
  *(char *)(param_1 + 0x10) = (char)iVar3;
  uVar1 = FUN_08010ec8(uVar2);
  *(undefined1 *)(param_1 + 0x11) = uVar1;
  uVar1 = FUN_08010ece(uVar2);
  *(undefined4 *)(param_1 + 0x14) = local_2c;
  *(undefined4 *)(param_1 + 0x18) = local_30;
  *(undefined4 *)(param_1 + 0x1c) = local_24;
  *(undefined4 *)(param_1 + 0x20) = local_28;
  *(undefined4 *)(param_1 + 0x24) = local_1c;
  *(undefined4 *)(param_1 + 0x28) = local_20;
  *(undefined1 *)(param_1 + 0x12) = uVar1;
  uVar5 = FUN_08010f0c(uVar2);
  *(undefined4 *)(param_1 + 0x2c) = uVar5;
  uVar5 = FUN_08010f12(uVar2);
  *(undefined4 *)(param_1 + 0x30) = uVar5;
  uVar2 = FUN_08010f1c(uVar2);
  *(undefined4 *)(param_1 + 0x34) = uVar2;
  uVar2 = FUN_0801126c(param_2);
  FUN_08010c84(uVar2,*DAT_08011874,*DAT_08011874 + 0xb,param_1 + 0x38);
  *(undefined1 *)(param_1 + 0x43) = 1;
  FUN_08010c74(local_34);
  return;
}

