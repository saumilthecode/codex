
undefined4 FUN_0802bfa4(undefined4 param_1,undefined4 param_2)

{
  uint uVar1;
  uint uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  uint uVar5;
  int iVar6;
  int local_28;
  undefined1 auStack_24 [8];
  
  uVar5 = 0;
LAB_0802bfb0:
  do {
    while( true ) {
      uVar1 = FUN_0802bf58(param_2);
      if (uVar1 == 0xb0) {
        if (uVar5 == 0) {
          FUN_0802b9b8(param_1,0,0xe,0,&local_28);
          FUN_0802ba00(param_1,0,0xf,0,&local_28);
        }
        return 0;
      }
      if ((int)(uVar1 << 0x18) < 0) break;
      FUN_0802b9b8(param_1,0,0xd,0,&local_28);
      iVar6 = (uVar1 & 0x3f) * 4 + 4;
      if ((int)(uVar1 << 0x19) < 0) {
        iVar6 = -iVar6;
      }
      local_28 = local_28 + iVar6;
LAB_0802c01c:
      FUN_0802ba00(param_1,0,0xd,0,&local_28);
    }
    uVar2 = uVar1 & 0xf0;
    if (uVar2 == 0x80) {
      uVar2 = FUN_0802bf58(param_2);
      uVar2 = uVar1 << 8 | uVar2;
      if (uVar2 == 0x8000) {
        return 9;
      }
      iVar6 = FUN_0802bd1e(param_1,0,(uVar2 & 0xfff) << 4);
      if (iVar6 != 0) {
        return 9;
      }
      uVar5 = uVar5 | (uVar2 << 0x14) >> 0x1f;
      goto LAB_0802bfb0;
    }
    if (uVar2 == 0x90) {
      if ((uVar1 & 0xd) == 0xd) {
        return 9;
      }
      FUN_0802b9b8(param_1,0,uVar1 & 0xf,0,&local_28);
      goto LAB_0802c01c;
    }
    if (uVar2 == 0xa0) {
      uVar2 = 0xff0 >> (~uVar1 & 7) & 0xff0;
      if ((int)(uVar1 << 0x1c) < 0) {
        uVar2 = uVar2 | 0x4000;
      }
LAB_0802c0a2:
      uVar3 = 0;
      uVar4 = uVar3;
    }
    else if (uVar2 == 0xb0) {
      switch(uVar1) {
      case 0xb1:
        uVar2 = FUN_0802bf58(param_2);
        if (0xe < (uVar2 - 1 & 0xff)) {
          return 9;
        }
        goto LAB_0802c0a2;
      case 0xb2:
        FUN_0802b9b8(param_1,0,0xd,0,&local_28);
        uVar1 = FUN_0802bf58(param_2);
        uVar2 = 2;
        while ((uVar1 & 0x80) != 0) {
          local_28 = ((uVar1 & 0x7f) << (uVar2 & 0xff)) + local_28;
          uVar2 = uVar2 + 7;
          uVar1 = FUN_0802bf58(param_2);
        }
        local_28 = local_28 + 0x204 + (uVar1 << (uVar2 & 0xff));
        goto LAB_0802c01c;
      case 0xb3:
        uVar1 = FUN_0802bf58(param_2);
        uVar3 = 1;
LAB_0802c12e:
        uVar2 = (uVar1 & 0xf0) << 0xc | (uVar1 & 0xf) + 1;
        uVar4 = uVar3;
        break;
      case 0xb4:
        uVar2 = 0;
        uVar3 = 5;
        uVar4 = 0;
        break;
      case 0xb5:
        FUN_0802b9b8(param_1,0,0xd,0,auStack_24);
        goto LAB_0802bfb0;
      default:
        if ((uVar1 & 0xfc) == 0xb4) {
          return 9;
        }
        uVar3 = 1;
        uVar2 = (uVar1 & 7) + 1 | 0x80000;
        uVar4 = uVar3;
      }
    }
    else if (uVar2 == 0xc0) {
      if (uVar1 == 0xc6) {
        uVar1 = FUN_0802bf58(param_2);
        uVar3 = 3;
        goto LAB_0802c12e;
      }
      if (uVar1 == 199) {
        uVar2 = FUN_0802bf58(param_2);
        if (0xe < (uVar2 - 1 & 0xff)) {
          return 9;
        }
        uVar3 = 4;
        uVar4 = 0;
      }
      else {
        if ((uVar1 & 0xf8) != 0xc0) {
          if (uVar1 == 200) {
            uVar1 = FUN_0802bf58(param_2);
            uVar2 = (uVar1 & 0xf) + 1 | ((uVar1 & 0xf0) + 0x10) * 0x1000;
          }
          else {
            if (uVar1 != 0xc9) {
              return 9;
            }
            uVar1 = FUN_0802bf58(param_2);
            uVar2 = (uVar1 & 0xf0) << 0xc | (uVar1 & 0xf) + 1;
          }
          goto LAB_0802c1dc;
        }
        uVar3 = 3;
        uVar2 = (uVar1 & 0xf) + 1 | 0xa0000;
        uVar4 = uVar3;
      }
    }
    else {
      if ((uVar1 & 0xf8) != 0xd0) {
        return 9;
      }
      uVar2 = (uVar1 & 7) + 1 | 0x80000;
LAB_0802c1dc:
      uVar3 = 1;
      uVar4 = 5;
    }
    iVar6 = FUN_0802bd1e(param_1,uVar3,uVar2,uVar4);
    if (iVar6 != 0) {
      return 9;
    }
  } while( true );
}

