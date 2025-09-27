
undefined8 FUN_0802965c(undefined4 param_1,uint param_2)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  
  iVar2 = (DAT_08029698 & param_2) + 0xfcc00000;
  if (iVar2 < 1) {
    uVar1 = -iVar2 >> 0x14;
    if (0x13fffff < -iVar2) {
      uVar3 = uVar1 - 0x14;
      iVar2 = uVar1 - 0x32;
      if ((int)uVar3 < 0x1f) {
        uVar1 = 0x80000000;
      }
      if (uVar3 == 0x1e || iVar2 < 0 != SBORROW4(uVar3,0x1e)) {
        uVar1 = uVar1 >> (uVar3 & 0xff);
      }
      else {
        uVar1 = 1;
      }
      iVar2 = 0;
      goto LAB_08029690;
    }
    iVar2 = 0x80000 >> (uVar1 & 0xff);
  }
  uVar1 = 0;
LAB_08029690:
  return CONCAT44(iVar2,uVar1);
}

