
undefined4 FUN_0800b46c(undefined4 param_1,uint param_2,undefined4 param_3)

{
  byte *pbVar1;
  undefined4 *puVar2;
  int iVar3;
  
  if (param_2 < 0x18) {
    if (param_2 == 0) {
      return 0;
    }
    switch(param_2) {
    case 1:
      pbVar1 = DAT_0800b4ec;
      break;
    case 2:
      pbVar1 = DAT_0800b4f0;
      break;
    case 3:
      pbVar1 = DAT_0800b4f4;
      break;
    case 4:
      pbVar1 = DAT_0800b4f8;
      break;
    default:
      goto switchD_0800b47a_caseD_5;
    case 7:
      pbVar1 = DAT_0800b500;
      break;
    case 8:
      pbVar1 = DAT_0800b4e4;
      break;
    case 0x10:
      pbVar1 = DAT_0800b4fc;
      break;
    case 0x17:
      pbVar1 = DAT_0800b504;
    }
  }
  else {
    pbVar1 = DAT_0800b4e0;
    if (((param_2 == 0x44) || (pbVar1 = DAT_0800b508, param_2 == 0x97)) ||
       (pbVar1 = DAT_0800b4e8, param_2 == 0x20)) goto LAB_0800b4ae;
switchD_0800b47a_caseD_5:
    pbVar1 = DAT_0800b4e0;
    if (((param_2 & 0x44) == 0) && (pbVar1 = DAT_0800b508, (param_2 & 0x97) == 0)) {
      return 0;
    }
  }
LAB_0800b4ae:
  puVar2 = (undefined4 *)*DAT_08025c30;
  iVar3 = *pbVar1 - 0x61;
  switch(*pbVar1) {
  case 0x61:
    iVar3 = FUN_08005de4(pbVar1,DAT_08025bf4,param_3,iVar3,DAT_08025c30);
    if (iVar3 == 0) {
      return 1;
    }
    iVar3 = FUN_08005de4(pbVar1,DAT_08025bf8);
    if (iVar3 == 0) {
      return 2;
    }
    break;
  case 0x62:
    iVar3 = FUN_08005de4(pbVar1,DAT_08025bfc,param_3,iVar3,DAT_08025c30);
    if (iVar3 == 0) {
      return 3;
    }
    break;
  case 99:
    iVar3 = FUN_08005de4(pbVar1,DAT_08025c00,param_3,iVar3,DAT_08025c30);
    if (iVar3 == 0) {
      return 4;
    }
    break;
  case 100:
    iVar3 = FUN_08005de4(pbVar1,DAT_08025c04,param_3,iVar3,DAT_08025c30);
    if (iVar3 == 0) {
      return 5;
    }
    break;
  case 0x67:
    iVar3 = FUN_08005de4(pbVar1,DAT_08025c08,param_3,iVar3,DAT_08025c30);
    if (iVar3 == 0) {
      return 6;
    }
    break;
  case 0x6c:
    iVar3 = FUN_08005de4(pbVar1,DAT_08025c0c,param_3,iVar3,DAT_08025c30);
    if (iVar3 == 0) {
      return 7;
    }
    break;
  case 0x70:
    iVar3 = FUN_08005de4(pbVar1,DAT_08025c10,param_3,iVar3,DAT_08025c30);
    if (iVar3 == 0) {
      return 8;
    }
    iVar3 = FUN_08005de4(pbVar1,DAT_08025c14);
    if (iVar3 == 0) {
      return 9;
    }
    break;
  case 0x73:
    iVar3 = FUN_08005de4(pbVar1,DAT_08025c18,param_3,iVar3,DAT_08025c30);
    if (iVar3 == 0) {
      return 10;
    }
    break;
  case 0x75:
    iVar3 = FUN_08005de4(pbVar1,DAT_08025c1c,param_3,iVar3,DAT_08025c30);
    if (iVar3 == 0) {
      return 0xb;
    }
    break;
  case 0x78:
    iVar3 = FUN_08005de4(pbVar1,DAT_08025c20,param_3,iVar3,DAT_08025c30);
    if (iVar3 == 0) {
      return 0xc;
    }
  }
  *puVar2 = 0x16;
  return 0;
}

