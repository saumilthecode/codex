
void FUN_080118e4(int param_1,undefined4 param_2)

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
  
  uVar2 = FUN_08011424(param_2);
  FUN_08010f40(&local_20,uVar2);
  FUN_080118c0(&local_30,&local_20);
  FUN_08010c74(local_20);
  FUN_08010f4e(&local_20,uVar2);
  FUN_080118c0(&local_28,&local_20);
  FUN_08010c74(local_20);
  FUN_08010f5c(&local_34,uVar2);
  FUN_080118c0(&local_20,&local_34);
  FUN_08010c74(local_34);
  FUN_08010f32(&local_34,uVar2);
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
  uVar1 = FUN_08010f26(uVar2);
  *(undefined1 *)(param_1 + 0x11) = uVar1;
  uVar1 = FUN_08010f2c(uVar2);
  *(undefined4 *)(param_1 + 0x14) = local_2c;
  *(undefined4 *)(param_1 + 0x18) = local_30;
  *(undefined4 *)(param_1 + 0x1c) = local_24;
  *(undefined4 *)(param_1 + 0x20) = local_28;
  *(undefined4 *)(param_1 + 0x24) = local_1c;
  *(undefined4 *)(param_1 + 0x28) = local_20;
  *(undefined1 *)(param_1 + 0x12) = uVar1;
  uVar5 = FUN_08010f6a(uVar2);
  *(undefined4 *)(param_1 + 0x2c) = uVar5;
  uVar5 = FUN_08010f70(uVar2);
  *(undefined4 *)(param_1 + 0x30) = uVar5;
  uVar2 = FUN_08010f7a(uVar2);
  *(undefined4 *)(param_1 + 0x34) = uVar2;
  uVar2 = FUN_0801126c(param_2);
  FUN_08010c84(uVar2,*DAT_080119d8,*DAT_080119d8 + 0xb,param_1 + 0x38);
  *(undefined1 *)(param_1 + 0x43) = 1;
  FUN_08010c74(local_34);
  return;
}

