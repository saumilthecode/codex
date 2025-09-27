
int * FUN_08018394(int *param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  char *pcVar6;
  char *pcVar7;
  int iVar8;
  undefined4 *puVar9;
  undefined4 local_30 [3];
  undefined2 local_24 [4];
  
  *param_1 = (int)(param_1 + 2);
  param_1[1] = 0;
  *(undefined1 *)(param_1 + 2) = 0;
  iVar8 = 0x3c;
  do {
    FUN_08017ea8(param_1,iVar8);
    pcVar6 = (char *)*param_1;
    *pcVar6 = '\0';
    iVar1 = FUN_080269dc(param_3,pcVar6,iVar8);
    if (iVar1 == 0) {
LAB_080183c4:
      iVar1 = FUN_08005ea0(pcVar6);
    }
    else if (iVar1 == 0x22) {
      iVar8 = iVar8 << 1;
      iVar1 = 0;
    }
    else {
      if (*pcVar6 != '\0') goto LAB_080183c4;
      puVar4 = DAT_0801843c;
      puVar5 = local_30;
      do {
        puVar9 = puVar5;
        puVar3 = puVar4;
        uVar2 = puVar3[1];
        *puVar9 = *puVar3;
        puVar9[1] = uVar2;
        puVar4 = puVar3 + 2;
        puVar5 = puVar9 + 2;
      } while (puVar4 != DAT_0801843c + 2);
      uVar2 = *puVar4;
      *(undefined2 *)(puVar9 + 3) = *(undefined2 *)(puVar3 + 3);
      puVar9[2] = uVar2;
      puVar4 = local_30;
      do {
        pcVar7 = pcVar6;
        puVar5 = puVar4;
        uVar2 = puVar5[1];
        puVar4 = puVar5 + 2;
        *(undefined4 *)pcVar7 = *puVar5;
        *(undefined4 *)(pcVar7 + 4) = uVar2;
        pcVar6 = pcVar7 + 8;
      } while (puVar4 != local_30 + 2);
      *(undefined4 *)(pcVar7 + 8) = *puVar4;
      pcVar7[0xc] = *(char *)(puVar5 + 3);
      iVar1 = 0xd;
    }
    param_1[1] = iVar1;
    *(undefined1 *)(*param_1 + iVar1) = 0;
    if (param_1[1] != 0) {
      return param_1;
    }
  } while( true );
}

