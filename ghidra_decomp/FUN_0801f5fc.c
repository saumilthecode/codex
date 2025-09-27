
void FUN_0801f5fc(char *param_1,char *param_2,undefined4 *param_3)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined8 uVar5;
  char *pcVar6;
  char *local_24;
  undefined4 *puStack_20;
  
  pcVar6 = param_1;
  local_24 = param_2;
  puStack_20 = param_3;
  iVar1 = FUN_0801f54c();
  if (iVar1 == 0) {
    *param_3 = 4;
    return;
  }
  uVar5 = FUN_08025720(param_1,&local_24);
  *(undefined8 *)param_2 = uVar5;
  uVar3 = 0;
  if ((local_24 == param_1) || (*local_24 != '\0')) {
    uVar4 = 0;
  }
  else {
    iVar2 = FUN_080066f8();
    if (iVar2 == 0) {
      iVar2 = FUN_080066f8((int)uVar5,(int)((ulonglong)uVar5 >> 0x20),0,DAT_0801f680,pcVar6);
      if (iVar2 == 0) goto LAB_0801f640;
      uVar3 = 0xffffffff;
      uVar4 = 0xffefffff;
    }
    else {
      uVar3 = 0xffffffff;
      uVar4 = DAT_0801f684;
    }
  }
  *(undefined4 *)param_2 = uVar3;
  *(undefined4 *)(param_2 + 4) = uVar4;
  *param_3 = 4;
LAB_0801f640:
  FUN_08028514(0,iVar1);
  thunk_FUN_080249c4(iVar1);
  return;
}

