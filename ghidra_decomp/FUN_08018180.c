
void FUN_08018180(undefined4 *param_1,undefined4 *param_2)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  undefined1 auStack_30 [20];
  
  if (param_1 == param_2) {
    return;
  }
  iVar1 = FUN_08017cd8();
  iVar2 = FUN_08017cd8(param_2);
  if (iVar1 == 0) {
    uVar3 = param_1[2];
    if (iVar2 == 0) {
      uVar4 = *param_1;
      *param_1 = *param_2;
      *param_2 = uVar4;
      param_1[2] = param_2[2];
    }
    else {
      FUN_08017cbe(param_1 + 2,param_2 + 2,param_2[1] + 1);
      *param_2 = *param_1;
      *param_1 = param_1 + 2;
    }
    param_2[2] = uVar3;
  }
  else {
    iVar1 = param_1[1];
    if (iVar2 == 0) {
      puVar5 = param_2 + 2;
      uVar3 = *puVar5;
      FUN_08017cbe(puVar5,param_1 + 2,iVar1 + 1);
      *param_1 = *param_2;
      *param_2 = puVar5;
      param_1[2] = uVar3;
    }
    else {
      iVar2 = param_2[1];
      if (iVar1 == 0) {
        if (iVar2 != 0) {
          FUN_08017cbe(param_1 + 2,param_2 + 2,iVar2 + 1);
          param_1[1] = param_2[1];
          param_2[1] = 0;
          *(undefined1 *)*param_2 = 0;
          return;
        }
      }
      else {
        puVar5 = param_2 + 2;
        puVar6 = param_1 + 2;
        if (iVar2 == 0) {
          FUN_08017cbe(puVar5,puVar6,iVar1 + 1);
          param_2[1] = param_1[1];
          param_1[1] = 0;
          *(undefined1 *)*param_1 = 0;
          return;
        }
        FUN_08017cbe(auStack_30,puVar5,iVar2 + 1);
        FUN_08017cbe(puVar5,puVar6,iVar1 + 1);
        FUN_08017cbe(puVar6,auStack_30,iVar2 + 1);
      }
    }
  }
  uVar3 = param_1[1];
  param_1[1] = param_2[1];
  param_2[1] = uVar3;
  return;
}

