
int FUN_080116cc(undefined1 *param_1,undefined4 param_2,uint param_3,uint param_4,int param_5,
                uint param_6,char param_7)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  undefined1 *puVar4;
  undefined8 uVar5;
  
  uVar5 = CONCAT44(param_4,param_3);
  puVar4 = param_1;
  if (param_7 == '\0') {
    if ((param_6 & 0x4a) == 0x40) {
      do {
        puVar4 = puVar4 + -1;
        *puVar4 = *(undefined1 *)((param_3 & 7) + param_5 + 4);
        param_3 = param_3 >> 3 | param_4 << 0x1d;
        param_4 = param_4 >> 3;
      } while (param_3 != 0 || param_4 != 0);
    }
    else {
      if ((param_6 & 0x4000) == 0) {
        iVar1 = 4;
      }
      else {
        iVar1 = 0x14;
      }
      do {
        puVar4 = puVar4 + -1;
        *puVar4 = *(undefined1 *)(param_5 + iVar1 + (param_3 & 0xf));
        param_3 = param_3 >> 4 | param_4 << 0x1c;
        param_4 = param_4 >> 4;
      } while (param_3 != 0 || param_4 != 0);
    }
  }
  else {
    do {
      uVar3 = (uint)((ulonglong)uVar5 >> 0x20);
      uVar2 = (uint)uVar5;
      iVar1 = 10;
      uVar5 = FUN_08006980(uVar2,uVar3,10,0);
      puVar4 = puVar4 + -1;
      *puVar4 = *(undefined1 *)(iVar1 + param_5 + 4);
    } while (uVar3 != 0 || uVar3 < (9 < uVar2));
  }
  return (int)param_1 - (int)puVar4;
}

