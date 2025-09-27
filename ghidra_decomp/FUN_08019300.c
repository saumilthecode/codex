
void FUN_08019300(int param_1,undefined4 param_2)

{
  undefined4 uVar1;
  int iVar2;
  char *pcVar3;
  undefined4 uVar4;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  
  uVar1 = FUN_08019038(param_2);
  FUN_08018afe(&local_20,uVar1);
  FUN_080192cc(&local_30,&local_20);
  FUN_08018900(local_20);
  FUN_08018b0c(&local_20,uVar1);
  FUN_080192cc(&local_28,&local_20);
  FUN_08018900(local_20);
  FUN_08018b1a(&local_34,uVar1);
  FUN_080192cc(&local_20,&local_34);
  FUN_08018900(local_34);
  FUN_08018af0(&local_34,uVar1);
  iVar2 = FUN_08018910(local_34);
  pcVar3 = (char *)thunk_FUN_08008466();
  FUN_0800a6c0(&local_34,pcVar3,iVar2,0);
  *(char **)(param_1 + 8) = pcVar3;
  *(int *)(param_1 + 0xc) = iVar2;
  if (iVar2 != 0) {
    if (*pcVar3 < '\x01') {
      iVar2 = 0;
    }
    else {
      iVar2 = 1;
    }
  }
  *(char *)(param_1 + 0x10) = (char)iVar2;
  uVar4 = FUN_08018ae4(uVar1);
  *(undefined4 *)(param_1 + 0x14) = uVar4;
  uVar4 = FUN_08018aea(uVar1);
  *(undefined4 *)(param_1 + 0x1c) = local_2c;
  *(undefined4 *)(param_1 + 0x20) = local_30;
  *(undefined4 *)(param_1 + 0x24) = local_24;
  *(undefined4 *)(param_1 + 0x28) = local_28;
  *(undefined4 *)(param_1 + 0x2c) = local_1c;
  *(undefined4 *)(param_1 + 0x30) = local_20;
  *(undefined4 *)(param_1 + 0x18) = uVar4;
  uVar4 = FUN_08018b28(uVar1);
  *(undefined4 *)(param_1 + 0x34) = uVar4;
  uVar4 = FUN_08018b2e(uVar1);
  *(undefined4 *)(param_1 + 0x38) = uVar4;
  uVar1 = FUN_08018b38(uVar1);
  *(undefined4 *)(param_1 + 0x3c) = uVar1;
  uVar1 = FUN_08018e8c(param_2);
  FUN_08018820(uVar1,*DAT_080193f4,*DAT_080193f4 + 0xb,param_1 + 0x40);
  *(undefined1 *)(param_1 + 0x6c) = 1;
  FUN_08018950(local_34);
  return;
}

