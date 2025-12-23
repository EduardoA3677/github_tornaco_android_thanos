.class public final Llyiahf/vczjk/tp3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/xg0;
.implements Llyiahf/vczjk/l23;
.implements Llyiahf/vczjk/cx6;
.implements Llyiahf/vczjk/uca;
.implements Llyiahf/vczjk/ci5;
.implements Llyiahf/vczjk/rw;
.implements Llyiahf/vczjk/uw;
.implements Llyiahf/vczjk/rv1;
.implements Lgithub/tornaco/android/thanos/core/profile/handle/ILog;
.implements Llyiahf/vczjk/i37;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/tp3;

.field public static final OooOOOO:Llyiahf/vczjk/hc;

.field public static final OooOOOo:Llyiahf/vczjk/tp3;

.field public static final synthetic OooOOo:Llyiahf/vczjk/tp3;

.field public static final OooOOo0:Llyiahf/vczjk/tp3;

.field public static final OooOOoo:Llyiahf/vczjk/tp3;

.field public static final OooOo0:Llyiahf/vczjk/tp3;

.field public static final OooOo00:Llyiahf/vczjk/tp3;


# instance fields
.field public final synthetic OooOOO0:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/tp3;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Llyiahf/vczjk/tp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/tp3;->OooOOO:Llyiahf/vczjk/tp3;

    new-instance v0, Llyiahf/vczjk/hc;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/tp3;->OooOOOO:Llyiahf/vczjk/hc;

    new-instance v0, Llyiahf/vczjk/tp3;

    const/4 v1, 0x3

    invoke-direct {v0, v1}, Llyiahf/vczjk/tp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/tp3;->OooOOOo:Llyiahf/vczjk/tp3;

    new-instance v0, Llyiahf/vczjk/tp3;

    const/4 v1, 0x4

    invoke-direct {v0, v1}, Llyiahf/vczjk/tp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/tp3;->OooOOo0:Llyiahf/vczjk/tp3;

    new-instance v0, Llyiahf/vczjk/tp3;

    const/4 v1, 0x5

    invoke-direct {v0, v1}, Llyiahf/vczjk/tp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/tp3;->OooOOo:Llyiahf/vczjk/tp3;

    new-instance v0, Llyiahf/vczjk/tp3;

    const/4 v1, 0x6

    invoke-direct {v0, v1}, Llyiahf/vczjk/tp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/tp3;->OooOOoo:Llyiahf/vczjk/tp3;

    new-instance v0, Llyiahf/vczjk/tp3;

    const/4 v1, 0x7

    invoke-direct {v0, v1}, Llyiahf/vczjk/tp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/tp3;->OooOo00:Llyiahf/vczjk/tp3;

    new-instance v0, Llyiahf/vczjk/tp3;

    const/16 v1, 0x8

    invoke-direct {v0, v1}, Llyiahf/vczjk/tp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/tp3;->OooOo0:Llyiahf/vczjk/tp3;

    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/tp3;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/tp3;)V
    .locals 0

    const/16 p1, 0x18

    iput p1, p0, Llyiahf/vczjk/tp3;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static OooOO0(Llyiahf/vczjk/dp8;Llyiahf/vczjk/o0oOO;ILlyiahf/vczjk/m3a;ZZ)Llyiahf/vczjk/o0OoOo0;
    .locals 18

    move-object/from16 v0, p1

    move-object/from16 v1, p3

    move/from16 v2, p5

    const/4 v3, 0x2

    const/4 v4, 0x0

    const/4 v5, 0x1

    sget-object v6, Llyiahf/vczjk/m3a;->OooOOOO:Llyiahf/vczjk/m3a;

    if-eq v1, v6, :cond_0

    move v7, v5

    goto :goto_0

    :cond_0
    move v7, v4

    :goto_0
    if-eqz v2, :cond_2

    if-nez p4, :cond_1

    goto :goto_1

    :cond_1
    move v8, v4

    goto :goto_2

    :cond_2
    :goto_1
    move v8, v5

    :goto_2
    const/4 v9, 0x0

    if-nez v7, :cond_3

    invoke-virtual/range {p0 .. p0}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object v7

    invoke-interface {v7}, Ljava/util/List;->isEmpty()Z

    move-result v7

    if-eqz v7, :cond_3

    new-instance v0, Llyiahf/vczjk/o0OoOo0;

    invoke-direct {v0, v9, v5, v4}, Llyiahf/vczjk/o0OoOo0;-><init>(Llyiahf/vczjk/dp8;IZ)V

    return-object v0

    :cond_3
    invoke-virtual/range {p0 .. p0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v7

    invoke-interface {v7}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v7

    if-nez v7, :cond_4

    new-instance v0, Llyiahf/vczjk/o0OoOo0;

    invoke-direct {v0, v9, v5, v4}, Llyiahf/vczjk/o0OoOo0;-><init>(Llyiahf/vczjk/dp8;IZ)V

    return-object v0

    :cond_4
    invoke-static/range {p2 .. p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    invoke-virtual {v0, v10}, Llyiahf/vczjk/o0oOO;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/f74;

    sget-object v11, Llyiahf/vczjk/z3a;->OooO00o:Llyiahf/vczjk/po;

    if-eq v1, v6, :cond_8

    instance-of v11, v7, Llyiahf/vczjk/by0;

    if-nez v11, :cond_5

    goto :goto_3

    :cond_5
    iget-object v11, v10, Llyiahf/vczjk/f74;->OooO0O0:Llyiahf/vczjk/dr5;

    sget-object v12, Llyiahf/vczjk/dr5;->OooOOO0:Llyiahf/vczjk/dr5;

    if-ne v11, v12, :cond_7

    sget-object v11, Llyiahf/vczjk/m3a;->OooOOO0:Llyiahf/vczjk/m3a;

    if-ne v1, v11, :cond_7

    move-object v11, v7

    check-cast v11, Llyiahf/vczjk/by0;

    sget-object v12, Llyiahf/vczjk/w64;->OooO00o:Ljava/lang/String;

    invoke-static {v11}, Llyiahf/vczjk/n72;->OooO0oO(Llyiahf/vczjk/v02;)Llyiahf/vczjk/ic3;

    move-result-object v12

    sget-object v13, Llyiahf/vczjk/w64;->OooOO0:Ljava/util/HashMap;

    invoke-virtual {v13, v12}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    move-result v12

    if-eqz v12, :cond_7

    invoke-static {v11}, Llyiahf/vczjk/n72;->OooO0oO(Llyiahf/vczjk/v02;)Llyiahf/vczjk/ic3;

    move-result-object v7

    invoke-virtual {v13, v7}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/hc3;

    if-eqz v7, :cond_6

    invoke-static {v11}, Llyiahf/vczjk/p72;->OooO0o0(Llyiahf/vczjk/v02;)Llyiahf/vczjk/hk4;

    move-result-object v11

    invoke-virtual {v11, v7}, Llyiahf/vczjk/hk4;->OooOO0(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/by0;

    move-result-object v7

    goto :goto_4

    :cond_6
    new-instance v0, Ljava/lang/IllegalArgumentException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Given class "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v2, " is not a mutable collection"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_7
    sget-object v11, Llyiahf/vczjk/dr5;->OooOOO:Llyiahf/vczjk/dr5;

    iget-object v12, v10, Llyiahf/vczjk/f74;->OooO0O0:Llyiahf/vczjk/dr5;

    if-ne v12, v11, :cond_8

    sget-object v11, Llyiahf/vczjk/m3a;->OooOOO:Llyiahf/vczjk/m3a;

    if-ne v1, v11, :cond_8

    check-cast v7, Llyiahf/vczjk/by0;

    sget-object v11, Llyiahf/vczjk/w64;->OooO00o:Ljava/lang/String;

    invoke-static {v7}, Llyiahf/vczjk/n72;->OooO0oO(Llyiahf/vczjk/v02;)Llyiahf/vczjk/ic3;

    move-result-object v11

    sget-object v12, Llyiahf/vczjk/w64;->OooOO0O:Ljava/util/HashMap;

    invoke-virtual {v12, v11}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    move-result v11

    if-eqz v11, :cond_8

    invoke-static {v7}, Llyiahf/vczjk/e86;->OooOOO(Llyiahf/vczjk/by0;)Llyiahf/vczjk/by0;

    move-result-object v7

    goto :goto_4

    :cond_8
    :goto_3
    move-object v7, v9

    :goto_4
    if-eq v1, v6, :cond_c

    iget-object v1, v10, Llyiahf/vczjk/f74;->OooO00o:Llyiahf/vczjk/x46;

    if-nez v1, :cond_9

    const/4 v1, -0x1

    goto :goto_5

    :cond_9
    sget-object v6, Llyiahf/vczjk/y3a;->OooO00o:[I

    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    move-result v1

    aget v1, v6, v1

    :goto_5
    if-eq v1, v5, :cond_b

    if-eq v1, v3, :cond_a

    goto :goto_6

    :cond_a
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    goto :goto_7

    :cond_b
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    goto :goto_7

    :cond_c
    :goto_6
    move-object v1, v9

    :goto_7
    if-eqz v7, :cond_d

    invoke-interface {v7}, Llyiahf/vczjk/gz0;->OooOo0o()Llyiahf/vczjk/n3a;

    move-result-object v6

    if-nez v6, :cond_e

    :cond_d
    invoke-virtual/range {p0 .. p0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v6

    :cond_e
    add-int/lit8 v11, p2, 0x1

    invoke-virtual/range {p0 .. p0}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object v12

    invoke-interface {v6}, Llyiahf/vczjk/n3a;->OooO0OO()Ljava/util/List;

    move-result-object v13

    const-string v14, "getParameters(...)"

    invoke-static {v13, v14}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v12}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v14

    invoke-interface {v13}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v15

    move/from16 v16, v3

    new-instance v3, Ljava/util/ArrayList;

    const/16 v5, 0xa

    invoke-static {v12, v5}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v12

    invoke-static {v13, v5}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v13

    invoke-static {v12, v13}, Ljava/lang/Math;->min(II)I

    move-result v12

    invoke-direct {v3, v12}, Ljava/util/ArrayList;-><init>(I)V

    :goto_8
    invoke-interface {v14}, Ljava/util/Iterator;->hasNext()Z

    move-result v12

    if-eqz v12, :cond_15

    invoke-interface {v15}, Ljava/util/Iterator;->hasNext()Z

    move-result v12

    if-eqz v12, :cond_15

    invoke-interface {v14}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v12

    invoke-interface {v15}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v13

    check-cast v13, Llyiahf/vczjk/t4a;

    check-cast v12, Llyiahf/vczjk/z4a;

    if-nez v8, :cond_f

    new-instance v5, Llyiahf/vczjk/w3;

    invoke-direct {v5, v9, v4}, Llyiahf/vczjk/w3;-><init>(Ljava/lang/Object;I)V

    goto :goto_9

    :cond_f
    invoke-virtual {v12}, Llyiahf/vczjk/z4a;->OooO0OO()Z

    move-result v5

    if-nez v5, :cond_10

    invoke-virtual {v12}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object v5

    invoke-virtual {v5}, Llyiahf/vczjk/uk4;->o00000O()Llyiahf/vczjk/iaa;

    move-result-object v5

    invoke-static {v5, v0, v11, v2}, Llyiahf/vczjk/tp3;->OooOO0o(Llyiahf/vczjk/iaa;Llyiahf/vczjk/o0oOO;IZ)Llyiahf/vczjk/w3;

    move-result-object v5

    goto :goto_9

    :cond_10
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    invoke-virtual {v0, v5}, Llyiahf/vczjk/o0oOO;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/f74;

    iget-object v5, v5, Llyiahf/vczjk/f74;->OooO00o:Llyiahf/vczjk/x46;

    sget-object v9, Llyiahf/vczjk/x46;->OooOOO0:Llyiahf/vczjk/x46;

    if-ne v5, v9, :cond_11

    invoke-virtual {v12}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object v5

    invoke-virtual {v5}, Llyiahf/vczjk/uk4;->o00000O()Llyiahf/vczjk/iaa;

    move-result-object v5

    new-instance v9, Llyiahf/vczjk/w3;

    invoke-static {v5}, Llyiahf/vczjk/u34;->Oooo0oO(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/dp8;

    move-result-object v0

    invoke-virtual {v0, v4}, Llyiahf/vczjk/dp8;->o0000Ooo(Z)Llyiahf/vczjk/dp8;

    move-result-object v0

    invoke-static {v5}, Llyiahf/vczjk/u34;->o00Oo0(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/dp8;

    move-result-object v5

    const/4 v4, 0x1

    invoke-virtual {v5, v4}, Llyiahf/vczjk/dp8;->o0000Ooo(Z)Llyiahf/vczjk/dp8;

    move-result-object v5

    invoke-static {v0, v5}, Llyiahf/vczjk/so8;->OooOoOO(Llyiahf/vczjk/dp8;Llyiahf/vczjk/dp8;)Llyiahf/vczjk/iaa;

    move-result-object v0

    invoke-direct {v9, v0, v4}, Llyiahf/vczjk/w3;-><init>(Ljava/lang/Object;I)V

    move-object v5, v9

    goto :goto_9

    :cond_11
    const/4 v4, 0x1

    new-instance v5, Llyiahf/vczjk/w3;

    const/4 v0, 0x0

    invoke-direct {v5, v0, v4}, Llyiahf/vczjk/w3;-><init>(Ljava/lang/Object;I)V

    :goto_9
    iget v0, v5, Llyiahf/vczjk/w3;->OooOOO0:I

    add-int/2addr v11, v0

    const-string v0, "getProjectionKind(...)"

    iget-object v4, v5, Llyiahf/vczjk/w3;->OooOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/iaa;

    if-eqz v4, :cond_12

    invoke-virtual {v12}, Llyiahf/vczjk/z4a;->OooO00o()Llyiahf/vczjk/cda;

    move-result-object v5

    invoke-static {v5, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v4, v5, v13}, Llyiahf/vczjk/fu6;->OooOO0(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;Llyiahf/vczjk/t4a;)Llyiahf/vczjk/f19;

    move-result-object v0

    goto :goto_a

    :cond_12
    if-eqz v7, :cond_13

    invoke-virtual {v12}, Llyiahf/vczjk/z4a;->OooO0OO()Z

    move-result v4

    if-nez v4, :cond_13

    invoke-virtual {v12}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object v4

    const-string v5, "getType(...)"

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v12}, Llyiahf/vczjk/z4a;->OooO00o()Llyiahf/vczjk/cda;

    move-result-object v5

    invoke-static {v5, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v4, v5, v13}, Llyiahf/vczjk/fu6;->OooOO0(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;Llyiahf/vczjk/t4a;)Llyiahf/vczjk/f19;

    move-result-object v0

    goto :goto_a

    :cond_13
    if-eqz v7, :cond_14

    invoke-static {v13}, Llyiahf/vczjk/l5a;->OooOO0(Llyiahf/vczjk/t4a;)Llyiahf/vczjk/f19;

    move-result-object v0

    goto :goto_a

    :cond_14
    const/4 v0, 0x0

    :goto_a
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move-object/from16 v0, p1

    const/4 v4, 0x0

    const/16 v5, 0xa

    const/4 v9, 0x0

    goto/16 :goto_8

    :cond_15
    sub-int v11, v11, p2

    if-nez v7, :cond_17

    if-nez v1, :cond_17

    invoke-virtual {v3}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_16

    goto :goto_c

    :cond_16
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_b
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_18

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/z4a;

    if-nez v2, :cond_17

    goto :goto_b

    :cond_17
    const/4 v2, 0x0

    goto :goto_d

    :cond_18
    :goto_c
    new-instance v0, Llyiahf/vczjk/o0OoOo0;

    const/4 v1, 0x0

    const/4 v2, 0x0

    invoke-direct {v0, v2, v11, v1}, Llyiahf/vczjk/o0OoOo0;-><init>(Llyiahf/vczjk/dp8;IZ)V

    return-object v0

    :goto_d
    invoke-virtual/range {p0 .. p0}, Llyiahf/vczjk/uk4;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v0

    sget-object v4, Llyiahf/vczjk/z3a;->OooO0O0:Llyiahf/vczjk/po;

    if-eqz v7, :cond_19

    goto :goto_e

    :cond_19
    move-object v4, v2

    :goto_e
    sget-object v5, Llyiahf/vczjk/z3a;->OooO00o:Llyiahf/vczjk/po;

    if-eqz v1, :cond_1a

    move-object v9, v5

    goto :goto_f

    :cond_1a
    move-object v9, v2

    :goto_f
    const/4 v2, 0x3

    new-array v2, v2, [Llyiahf/vczjk/ko;

    const/16 v17, 0x0

    aput-object v0, v2, v17

    const/4 v0, 0x1

    aput-object v4, v2, v0

    aput-object v9, v2, v16

    invoke-static {v2}, Llyiahf/vczjk/sy;->o0OO00O([Ljava/lang/Object;)Ljava/util/ArrayList;

    move-result-object v2

    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    move-result v4

    if-eqz v4, :cond_21

    if-eq v4, v0, :cond_1b

    new-instance v4, Llyiahf/vczjk/po;

    invoke-static {v2}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v2

    invoke-direct {v4, v0, v2}, Llyiahf/vczjk/po;-><init>(ILjava/util/List;)V

    goto :goto_10

    :cond_1b
    invoke-static {v2}, Llyiahf/vczjk/d21;->o00000o0(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v2

    move-object v4, v2

    check-cast v4, Llyiahf/vczjk/ko;

    :goto_10
    invoke-static {v4}, Llyiahf/vczjk/br6;->Oooo00o(Llyiahf/vczjk/ko;)Llyiahf/vczjk/d3a;

    move-result-object v2

    invoke-virtual/range {p0 .. p0}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object v4

    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v5

    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v7

    new-instance v8, Ljava/util/ArrayList;

    const/16 v9, 0xa

    invoke-static {v3, v9}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v3

    invoke-static {v4, v9}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v4

    invoke-static {v3, v4}, Ljava/lang/Math;->min(II)I

    move-result v3

    invoke-direct {v8, v3}, Ljava/util/ArrayList;-><init>(I)V

    :goto_11
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_1d

    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_1d

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/z4a;

    check-cast v3, Llyiahf/vczjk/z4a;

    if-nez v3, :cond_1c

    goto :goto_12

    :cond_1c
    move-object v4, v3

    :goto_12
    invoke-virtual {v8, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_11

    :cond_1d
    if-eqz v1, :cond_1e

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v3

    goto :goto_13

    :cond_1e
    invoke-virtual/range {p0 .. p0}, Llyiahf/vczjk/uk4;->o000000o()Z

    move-result v3

    :goto_13
    invoke-static {v8, v2, v6, v3}, Llyiahf/vczjk/so8;->Oooo0oO(Ljava/util/List;Llyiahf/vczjk/d3a;Llyiahf/vczjk/n3a;Z)Llyiahf/vczjk/dp8;

    move-result-object v2

    iget-boolean v3, v10, Llyiahf/vczjk/f74;->OooO0OO:Z

    if-eqz v3, :cond_1f

    new-instance v3, Llyiahf/vczjk/v26;

    invoke-direct {v3, v2}, Llyiahf/vczjk/v26;-><init>(Llyiahf/vczjk/dp8;)V

    move-object v2, v3

    :cond_1f
    if-eqz v1, :cond_20

    iget-boolean v1, v10, Llyiahf/vczjk/f74;->OooO0Oo:Z

    if-eqz v1, :cond_20

    move v4, v0

    goto :goto_14

    :cond_20
    move/from16 v4, v17

    :goto_14
    new-instance v0, Llyiahf/vczjk/o0OoOo0;

    invoke-direct {v0, v2, v11, v4}, Llyiahf/vczjk/o0OoOo0;-><init>(Llyiahf/vczjk/dp8;IZ)V

    return-object v0

    :cond_21
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "At least one Annotations object expected"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static OooOO0o(Llyiahf/vczjk/iaa;Llyiahf/vczjk/o0oOO;IZ)Llyiahf/vczjk/w3;
    .locals 16

    move-object/from16 v0, p0

    invoke-static {v0}, Llyiahf/vczjk/jp8;->OooOooO(Llyiahf/vczjk/uk4;)Z

    move-result v1

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    new-instance v0, Llyiahf/vczjk/w3;

    const/4 v1, 0x1

    invoke-direct {v0, v2, v1}, Llyiahf/vczjk/w3;-><init>(Ljava/lang/Object;I)V

    return-object v0

    :cond_0
    instance-of v1, v0, Llyiahf/vczjk/k23;

    if-eqz v1, :cond_b

    instance-of v7, v0, Llyiahf/vczjk/qg7;

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/k23;

    sget-object v6, Llyiahf/vczjk/m3a;->OooOOO0:Llyiahf/vczjk/m3a;

    iget-object v3, v1, Llyiahf/vczjk/k23;->OooOOO:Llyiahf/vczjk/dp8;

    move-object/from16 v4, p1

    move/from16 v5, p2

    move/from16 v8, p3

    invoke-static/range {v3 .. v8}, Llyiahf/vczjk/tp3;->OooOO0(Llyiahf/vczjk/dp8;Llyiahf/vczjk/o0oOO;ILlyiahf/vczjk/m3a;ZZ)Llyiahf/vczjk/o0OoOo0;

    move-result-object v9

    sget-object v6, Llyiahf/vczjk/m3a;->OooOOO:Llyiahf/vczjk/m3a;

    iget-object v3, v1, Llyiahf/vczjk/k23;->OooOOOO:Llyiahf/vczjk/dp8;

    move-object/from16 v4, p1

    move/from16 v5, p2

    move/from16 v8, p3

    invoke-static/range {v3 .. v8}, Llyiahf/vczjk/tp3;->OooOO0(Llyiahf/vczjk/dp8;Llyiahf/vczjk/o0oOO;ILlyiahf/vczjk/m3a;ZZ)Llyiahf/vczjk/o0OoOo0;

    move-result-object v3

    iget-object v4, v3, Llyiahf/vczjk/o0OoOo0;->OooO0OO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/dp8;

    iget-object v5, v9, Llyiahf/vczjk/o0OoOo0;->OooO0OO:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/dp8;

    if-nez v5, :cond_1

    if-nez v4, :cond_1

    goto :goto_2

    :cond_1
    iget-boolean v2, v9, Llyiahf/vczjk/o0OoOo0;->OooO0O0:Z

    if-nez v2, :cond_8

    iget-boolean v2, v3, Llyiahf/vczjk/o0OoOo0;->OooO0O0:Z

    if-eqz v2, :cond_2

    goto :goto_0

    :cond_2
    iget-object v0, v1, Llyiahf/vczjk/k23;->OooOOOO:Llyiahf/vczjk/dp8;

    iget-object v1, v1, Llyiahf/vczjk/k23;->OooOOO:Llyiahf/vczjk/dp8;

    if-eqz v7, :cond_5

    new-instance v2, Llyiahf/vczjk/qg7;

    if-nez v5, :cond_3

    move-object v5, v1

    :cond_3
    if-nez v4, :cond_4

    move-object v4, v0

    :cond_4
    invoke-direct {v2, v5, v4}, Llyiahf/vczjk/qg7;-><init>(Llyiahf/vczjk/dp8;Llyiahf/vczjk/dp8;)V

    goto :goto_2

    :cond_5
    if-nez v5, :cond_6

    move-object v5, v1

    :cond_6
    if-nez v4, :cond_7

    move-object v4, v0

    :cond_7
    invoke-static {v5, v4}, Llyiahf/vczjk/so8;->OooOoOO(Llyiahf/vczjk/dp8;Llyiahf/vczjk/dp8;)Llyiahf/vczjk/iaa;

    move-result-object v2

    goto :goto_2

    :cond_8
    :goto_0
    if-eqz v4, :cond_a

    if-nez v5, :cond_9

    move-object v5, v4

    :cond_9
    invoke-static {v5, v4}, Llyiahf/vczjk/so8;->OooOoOO(Llyiahf/vczjk/dp8;Llyiahf/vczjk/dp8;)Llyiahf/vczjk/iaa;

    move-result-object v5

    goto :goto_1

    :cond_a
    invoke-static {v5}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    :goto_1
    invoke-static {v0, v5}, Llyiahf/vczjk/qu6;->OooOo0o(Llyiahf/vczjk/iaa;Llyiahf/vczjk/uk4;)Llyiahf/vczjk/iaa;

    move-result-object v2

    :goto_2
    new-instance v0, Llyiahf/vczjk/w3;

    iget v1, v9, Llyiahf/vczjk/o0OoOo0;->OooO00o:I

    invoke-direct {v0, v2, v1}, Llyiahf/vczjk/w3;-><init>(Ljava/lang/Object;I)V

    return-object v0

    :cond_b
    instance-of v1, v0, Llyiahf/vczjk/dp8;

    if-eqz v1, :cond_d

    move-object v10, v0

    check-cast v10, Llyiahf/vczjk/dp8;

    sget-object v13, Llyiahf/vczjk/m3a;->OooOOOO:Llyiahf/vczjk/m3a;

    const/4 v14, 0x0

    move-object/from16 v11, p1

    move/from16 v12, p2

    move/from16 v15, p3

    invoke-static/range {v10 .. v15}, Llyiahf/vczjk/tp3;->OooOO0(Llyiahf/vczjk/dp8;Llyiahf/vczjk/o0oOO;ILlyiahf/vczjk/m3a;ZZ)Llyiahf/vczjk/o0OoOo0;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/w3;

    iget-boolean v3, v1, Llyiahf/vczjk/o0OoOo0;->OooO0O0:Z

    iget-object v4, v1, Llyiahf/vczjk/o0OoOo0;->OooO0OO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/dp8;

    if-eqz v3, :cond_c

    invoke-static {v0, v4}, Llyiahf/vczjk/qu6;->OooOo0o(Llyiahf/vczjk/iaa;Llyiahf/vczjk/uk4;)Llyiahf/vczjk/iaa;

    move-result-object v4

    :cond_c
    iget v0, v1, Llyiahf/vczjk/o0OoOo0;->OooO00o:I

    invoke-direct {v2, v4, v0}, Llyiahf/vczjk/w3;-><init>(Ljava/lang/Object;I)V

    return-object v2

    :cond_d
    new-instance v0, Llyiahf/vczjk/k61;

    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    throw v0
.end method


# virtual methods
.method public OooO(Llyiahf/vczjk/d64;Llyiahf/vczjk/co0;ZLlyiahf/vczjk/ld9;Llyiahf/vczjk/bo;Llyiahf/vczjk/x3a;ZLlyiahf/vczjk/oe3;)Llyiahf/vczjk/uk4;
    .locals 6

    new-instance v0, Llyiahf/vczjk/bv0;

    const/4 v5, 0x0

    move-object v1, p2

    move v2, p3

    move-object v3, p4

    move-object v4, p5

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/bv0;-><init>(Llyiahf/vczjk/x02;ZLlyiahf/vczjk/ld9;Llyiahf/vczjk/bo;Z)V

    move-object p2, v0

    invoke-interface {p8, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p3

    check-cast p3, Llyiahf/vczjk/uk4;

    invoke-interface {p1}, Llyiahf/vczjk/eo0;->OooOOO0()Ljava/util/Collection;

    move-result-object p1

    const-string p4, "getOverriddenDescriptors(...)"

    invoke-static {p1, p4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Ljava/lang/Iterable;

    new-instance p4, Ljava/util/ArrayList;

    const/16 p5, 0xa

    invoke-static {p1, p5}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result p5

    invoke-direct {p4, p5}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result p1

    if-eqz p1, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/eo0;

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-interface {p8, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/uk4;

    invoke-virtual {p4, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    move-object p1, p0

    move-object p5, p6

    move p6, p7

    invoke-virtual/range {p1 .. p6}, Llyiahf/vczjk/tp3;->OooO0OO(Llyiahf/vczjk/bv0;Llyiahf/vczjk/uk4;Ljava/util/List;Llyiahf/vczjk/x3a;Z)Llyiahf/vczjk/uk4;

    move-result-object p2

    return-object p2
.end method

.method public OooO00o(Landroid/app/Activity;)Landroid/graphics/Rect;
    .locals 5

    new-instance v0, Landroid/graphics/Rect;

    invoke-direct {v0}, Landroid/graphics/Rect;-><init>()V

    invoke-virtual {p1}, Landroid/app/Activity;->getWindowManager()Landroid/view/WindowManager;

    move-result-object v1

    invoke-interface {v1}, Landroid/view/WindowManager;->getDefaultDisplay()Landroid/view/Display;

    move-result-object v1

    invoke-virtual {v1, v0}, Landroid/view/Display;->getRectSize(Landroid/graphics/Rect;)V

    invoke-virtual {p1}, Landroid/app/Activity;->isInMultiWindowMode()Z

    move-result v2

    if-nez v2, :cond_2

    new-instance v2, Landroid/graphics/Point;

    invoke-direct {v2}, Landroid/graphics/Point;-><init>()V

    invoke-virtual {v1, v2}, Landroid/view/Display;->getRealSize(Landroid/graphics/Point;)V

    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object p1

    const-string v1, "dimen"

    const-string v3, "android"

    const-string v4, "navigation_bar_height"

    invoke-virtual {p1, v4, v1, v3}, Landroid/content/res/Resources;->getIdentifier(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I

    move-result v1

    if-lez v1, :cond_0

    invoke-virtual {p1, v1}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    move-result p1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    iget v1, v0, Landroid/graphics/Rect;->bottom:I

    add-int/2addr v1, p1

    iget v3, v2, Landroid/graphics/Point;->y:I

    if-ne v1, v3, :cond_1

    iput v1, v0, Landroid/graphics/Rect;->bottom:I

    return-object v0

    :cond_1
    iget v1, v0, Landroid/graphics/Rect;->right:I

    add-int/2addr v1, p1

    iget p1, v2, Landroid/graphics/Point;->x:I

    if-ne v1, p1, :cond_2

    iput v1, v0, Landroid/graphics/Rect;->right:I

    :cond_2
    return-object v0
.end method

.method public OooO0O0(Llyiahf/vczjk/ko;Llyiahf/vczjk/ko;)V
    .locals 2

    new-instance v0, Ljava/util/HashSet;

    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/un;

    invoke-interface {v1}, Llyiahf/vczjk/un;->OooO0oo()Llyiahf/vczjk/hc3;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p2

    if-eqz p2, :cond_1

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/un;

    invoke-interface {p2}, Llyiahf/vczjk/un;->OooO0oo()Llyiahf/vczjk/hc3;

    move-result-object p2

    invoke-virtual {v0, p2}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_1
    return-void
.end method

.method public OooO0OO(Llyiahf/vczjk/bv0;Llyiahf/vczjk/uk4;Ljava/util/List;Llyiahf/vczjk/x3a;Z)Llyiahf/vczjk/uk4;
    .locals 24

    move-object/from16 v0, p1

    move-object/from16 v1, p2

    const-string v4, "<this>"

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual/range {p1 .. p2}, Llyiahf/vczjk/bv0;->OooO(Llyiahf/vczjk/yk4;)Ljava/util/ArrayList;

    move-result-object v4

    new-instance v5, Ljava/util/ArrayList;

    const/16 v6, 0xa

    move-object/from16 v7, p3

    invoke-static {v7, v6}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v6

    invoke-direct {v5, v6}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v7}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v6

    :goto_0
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_0

    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/yk4;

    invoke-virtual {v0, v8}, Llyiahf/vczjk/bv0;->OooO(Llyiahf/vczjk/yk4;)Ljava/util/ArrayList;

    move-result-object v8

    invoke-virtual {v5, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    iget-object v6, v0, Llyiahf/vczjk/bv0;->OooO0Oo:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/ld9;

    iget-boolean v8, v0, Llyiahf/vczjk/bv0;->OooO00o:Z

    if-eqz v8, :cond_3

    invoke-interface {v7}, Ljava/util/Collection;->isEmpty()Z

    move-result v9

    if-eqz v9, :cond_1

    goto :goto_1

    :cond_1
    invoke-interface {v7}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v7

    :cond_2
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    move-result v9

    if-eqz v9, :cond_3

    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/yk4;

    const-string v10, "other"

    invoke-static {v9, v10}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v10, v6, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v10, Llyiahf/vczjk/s64;

    check-cast v9, Llyiahf/vczjk/uk4;

    iget-object v10, v10, Llyiahf/vczjk/s64;->OooOo0:Llyiahf/vczjk/v06;

    invoke-virtual {v10, v1, v9}, Llyiahf/vczjk/v06;->OooO00o(Llyiahf/vczjk/uk4;Llyiahf/vczjk/uk4;)Z

    move-result v9

    if-nez v9, :cond_2

    const/4 v7, 0x1

    goto :goto_2

    :cond_3
    :goto_1
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    move-result v7

    :goto_2
    new-array v9, v7, [Llyiahf/vczjk/f74;

    const/4 v10, 0x0

    :goto_3
    if-ge v10, v7, :cond_50

    invoke-virtual {v4, v10}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Llyiahf/vczjk/o0O00o0;

    iget-object v12, v11, Llyiahf/vczjk/o0O00o0;->OooO00o:Llyiahf/vczjk/yk4;

    sget-object v13, Llyiahf/vczjk/uk2;->OooOo0:Llyiahf/vczjk/uk2;

    iget-object v15, v0, Llyiahf/vczjk/bv0;->OooO0OO:Ljava/lang/Object;

    check-cast v15, Llyiahf/vczjk/x02;

    iget-object v3, v11, Llyiahf/vczjk/o0O00o0;->OooO0OO:Llyiahf/vczjk/t4a;

    if-nez v12, :cond_5

    if-eqz v3, :cond_4

    invoke-interface {v3}, Llyiahf/vczjk/t4a;->Oooo0OO()Llyiahf/vczjk/cda;

    move-result-object v12

    const-string v14, "getVariance(...)"

    invoke-static {v12, v14}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v12}, Llyiahf/vczjk/xt6;->OooOoO0(Llyiahf/vczjk/cda;)Llyiahf/vczjk/o5a;

    move-result-object v12

    goto :goto_4

    :cond_4
    const/4 v12, 0x0

    :goto_4
    sget-object v14, Llyiahf/vczjk/o5a;->OooOOO0:Llyiahf/vczjk/o5a;

    if-ne v12, v14, :cond_5

    sget-object v3, Llyiahf/vczjk/f74;->OooO0o0:Llyiahf/vczjk/f74;

    move-object/from16 v21, v4

    move-object/from16 v23, v5

    move-object/from16 v22, v6

    const/4 v4, 0x0

    goto/16 :goto_25

    :cond_5
    if-nez v3, :cond_6

    const/4 v12, 0x1

    goto :goto_5

    :cond_6
    const/4 v12, 0x0

    :goto_5
    sget-object v14, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    iget-object v2, v11, Llyiahf/vczjk/o0O00o0;->OooO00o:Llyiahf/vczjk/yk4;

    if-eqz v2, :cond_7

    move-object/from16 v16, v2

    check-cast v16, Llyiahf/vczjk/uk4;

    invoke-virtual/range {v16 .. v16}, Llyiahf/vczjk/uk4;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v16

    move-object/from16 v1, v16

    goto :goto_6

    :cond_7
    move-object v1, v14

    :goto_6
    if-eqz v2, :cond_8

    invoke-virtual {v13, v2}, Llyiahf/vczjk/uk2;->Ooooooo(Llyiahf/vczjk/yk4;)Llyiahf/vczjk/n3a;

    move-result-object v2

    if-eqz v2, :cond_8

    invoke-static {v2}, Llyiahf/vczjk/m6a;->OoooOo0(Llyiahf/vczjk/o3a;)Llyiahf/vczjk/t4a;

    move-result-object v2

    move-object/from16 v16, v2

    goto :goto_7

    :cond_8
    const/16 v16, 0x0

    :goto_7
    sget-object v2, Llyiahf/vczjk/bo;->OooOOo0:Llyiahf/vczjk/bo;

    move-object/from16 v17, v3

    iget-object v3, v0, Llyiahf/vczjk/bv0;->OooO0o0:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/bo;

    if-ne v3, v2, :cond_9

    const/4 v2, 0x1

    goto :goto_8

    :cond_9
    const/4 v2, 0x0

    :goto_8
    if-nez v12, :cond_a

    move/from16 v18, v2

    goto :goto_9

    :cond_a
    move/from16 v18, v2

    if-nez v2, :cond_b

    iget-object v2, v6, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/s64;

    iget-object v2, v2, Llyiahf/vczjk/s64;->OooOo00:Llyiahf/vczjk/wp3;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_b
    if-eqz v15, :cond_c

    invoke-interface {v15}, Llyiahf/vczjk/gm;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v2

    if-eqz v2, :cond_c

    move-object v14, v2

    :cond_c
    invoke-static {v14, v1}, Llyiahf/vczjk/d21;->o000000o(Ljava/lang/Iterable;Ljava/lang/Iterable;)Ljava/util/ArrayList;

    move-result-object v1

    :goto_9
    iget-object v2, v6, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/s64;

    iget-object v2, v2, Llyiahf/vczjk/s64;->OooOOo0:Llyiahf/vczjk/eo;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    const/4 v14, 0x0

    :goto_a
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v19

    if-eqz v19, :cond_10

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v19

    move-object/from16 v20, v1

    invoke-static/range {v19 .. v19}, Llyiahf/vczjk/eo;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/hc3;

    move-result-object v1

    sget-object v19, Llyiahf/vczjk/ed4;->OooOOO:Ljava/util/Set;

    move-object/from16 v21, v2

    move-object/from16 v2, v19

    check-cast v2, Ljava/lang/Iterable;

    invoke-static {v2, v1}, Llyiahf/vczjk/d21;->OoooooO(Ljava/lang/Iterable;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_d

    sget-object v1, Llyiahf/vczjk/dr5;->OooOOO0:Llyiahf/vczjk/dr5;

    goto :goto_b

    :cond_d
    sget-object v2, Llyiahf/vczjk/ed4;->OooOOOO:Ljava/util/Set;

    check-cast v2, Ljava/lang/Iterable;

    invoke-static {v2, v1}, Llyiahf/vczjk/d21;->OoooooO(Ljava/lang/Iterable;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_f

    sget-object v1, Llyiahf/vczjk/dr5;->OooOOO:Llyiahf/vczjk/dr5;

    :goto_b
    if-eqz v14, :cond_e

    if-eq v14, v1, :cond_e

    const/4 v14, 0x0

    goto :goto_c

    :cond_e
    move-object v14, v1

    :cond_f
    move-object/from16 v1, v20

    move-object/from16 v2, v21

    goto :goto_a

    :cond_10
    move-object/from16 v20, v1

    :goto_c
    iget-object v1, v6, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/s64;

    new-instance v2, Llyiahf/vczjk/o0oOO;

    move-object/from16 v19, v3

    const/4 v3, 0x0

    invoke-direct {v2, v3, v0, v11}, Llyiahf/vczjk/o0oOO;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    iget-object v1, v1, Llyiahf/vczjk/s64;->OooOOo0:Llyiahf/vczjk/eo;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-interface/range {v20 .. v20}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v3

    move-object/from16 v20, v3

    const/4 v3, 0x0

    :goto_d
    invoke-interface/range {v20 .. v20}, Ljava/util/Iterator;->hasNext()Z

    move-result v21

    if-eqz v21, :cond_1c

    move-object/from16 v21, v4

    invoke-interface/range {v20 .. v20}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    invoke-virtual {v2, v4}, Llyiahf/vczjk/o0oOO;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v22

    check-cast v22, Ljava/lang/Boolean;

    move-object/from16 v23, v5

    invoke-virtual/range {v22 .. v22}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v5

    invoke-virtual {v1, v4, v5}, Llyiahf/vczjk/eo;->OooO0oO(Ljava/lang/Object;Z)Llyiahf/vczjk/y46;

    move-result-object v5

    if-eqz v5, :cond_11

    move-object/from16 p3, v1

    move-object/from16 v22, v6

    const/4 v4, 0x0

    goto :goto_13

    :cond_11
    invoke-virtual {v1, v4}, Llyiahf/vczjk/eo;->OooO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    if-nez v5, :cond_13

    move-object/from16 v22, v6

    :cond_12
    move-object/from16 p3, v1

    const/4 v4, 0x0

    goto :goto_12

    :cond_13
    invoke-virtual {v1, v4}, Llyiahf/vczjk/eo;->OooO0oo(Ljava/lang/Object;)Llyiahf/vczjk/yq7;

    move-result-object v4

    if-eqz v4, :cond_14

    :goto_e
    move-object/from16 v22, v6

    goto :goto_f

    :cond_14
    iget-object v4, v1, Llyiahf/vczjk/eo;->OooO00o:Llyiahf/vczjk/c74;

    iget-object v4, v4, Llyiahf/vczjk/c74;->OooO00o:Llyiahf/vczjk/ad4;

    iget-object v4, v4, Llyiahf/vczjk/ad4;->OooO00o:Llyiahf/vczjk/yq7;

    goto :goto_e

    :goto_f
    sget-object v6, Llyiahf/vczjk/yq7;->OooOOO0:Llyiahf/vczjk/yq7;

    if-ne v4, v6, :cond_15

    move-object/from16 p3, v1

    const/4 v4, 0x0

    const/4 v5, 0x0

    goto :goto_13

    :cond_15
    invoke-virtual {v2, v5}, Llyiahf/vczjk/o0oOO;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Ljava/lang/Boolean;

    invoke-virtual {v6}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v6

    invoke-virtual {v1, v5, v6}, Llyiahf/vczjk/eo;->OooO0oO(Ljava/lang/Object;Z)Llyiahf/vczjk/y46;

    move-result-object v5

    if-eqz v5, :cond_12

    sget-object v6, Llyiahf/vczjk/yq7;->OooOOO:Llyiahf/vczjk/yq7;

    if-ne v4, v6, :cond_16

    const/4 v6, 0x1

    :goto_10
    move-object/from16 p3, v1

    const/4 v1, 0x1

    const/4 v4, 0x0

    goto :goto_11

    :cond_16
    const/4 v6, 0x0

    goto :goto_10

    :goto_11
    invoke-static {v5, v4, v6, v1}, Llyiahf/vczjk/y46;->OooO00o(Llyiahf/vczjk/y46;Llyiahf/vczjk/x46;ZI)Llyiahf/vczjk/y46;

    move-result-object v5

    goto :goto_13

    :goto_12
    move-object v5, v4

    :goto_13
    if-nez v3, :cond_17

    goto :goto_14

    :cond_17
    if-eqz v5, :cond_1b

    invoke-virtual {v5, v3}, Llyiahf/vczjk/y46;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_18

    goto :goto_15

    :cond_18
    iget-boolean v1, v3, Llyiahf/vczjk/y46;->OooO0O0:Z

    iget-boolean v6, v5, Llyiahf/vczjk/y46;->OooO0O0:Z

    if-eqz v6, :cond_19

    if-nez v1, :cond_19

    goto :goto_15

    :cond_19
    if-nez v6, :cond_1a

    if-eqz v1, :cond_1a

    :goto_14
    move-object v3, v5

    goto :goto_15

    :cond_1a
    move-object v3, v4

    goto :goto_16

    :cond_1b
    :goto_15
    move-object/from16 v1, p3

    move-object/from16 v4, v21

    move-object/from16 v6, v22

    move-object/from16 v5, v23

    goto/16 :goto_d

    :cond_1c
    move-object/from16 v21, v4

    move-object/from16 v23, v5

    move-object/from16 v22, v6

    const/4 v4, 0x0

    :goto_16
    if-eqz v3, :cond_1e

    new-instance v1, Llyiahf/vczjk/f74;

    sget-object v2, Llyiahf/vczjk/x46;->OooOOOO:Llyiahf/vczjk/x46;

    iget-object v5, v3, Llyiahf/vczjk/y46;->OooO00o:Llyiahf/vczjk/x46;

    if-ne v5, v2, :cond_1d

    if-eqz v16, :cond_1d

    const/4 v2, 0x1

    goto :goto_17

    :cond_1d
    const/4 v2, 0x0

    :goto_17
    iget-boolean v3, v3, Llyiahf/vczjk/y46;->OooO0O0:Z

    invoke-direct {v1, v5, v14, v2, v3}, Llyiahf/vczjk/f74;-><init>(Llyiahf/vczjk/x46;Llyiahf/vczjk/dr5;ZZ)V

    move-object v3, v1

    goto/16 :goto_25

    :cond_1e
    if-nez v12, :cond_20

    if-eqz v18, :cond_1f

    goto :goto_18

    :cond_1f
    sget-object v3, Llyiahf/vczjk/bo;->OooOOOo:Llyiahf/vczjk/bo;

    goto :goto_19

    :cond_20
    :goto_18
    move-object/from16 v3, v19

    :goto_19
    iget-object v1, v11, Llyiahf/vczjk/o0O00o0;->OooO0O0:Llyiahf/vczjk/g74;

    if-eqz v1, :cond_21

    iget-object v1, v1, Llyiahf/vczjk/g74;->OooO00o:Ljava/util/EnumMap;

    invoke-virtual {v1, v3}, Ljava/util/EnumMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/g64;

    goto :goto_1a

    :cond_21
    move-object v1, v4

    :goto_1a
    if-eqz v16, :cond_22

    invoke-static/range {v16 .. v16}, Llyiahf/vczjk/bv0;->OooO0OO(Llyiahf/vczjk/t4a;)Llyiahf/vczjk/y46;

    move-result-object v2

    goto :goto_1b

    :cond_22
    move-object v2, v4

    :goto_1b
    const/4 v3, 0x2

    if-eqz v2, :cond_23

    sget-object v5, Llyiahf/vczjk/x46;->OooOOOO:Llyiahf/vczjk/x46;

    const/4 v6, 0x0

    invoke-static {v2, v5, v6, v3}, Llyiahf/vczjk/y46;->OooO00o(Llyiahf/vczjk/y46;Llyiahf/vczjk/x46;ZI)Llyiahf/vczjk/y46;

    move-result-object v5

    goto :goto_1c

    :cond_23
    if-eqz v1, :cond_24

    iget-object v5, v1, Llyiahf/vczjk/g64;->OooO00o:Llyiahf/vczjk/y46;

    goto :goto_1c

    :cond_24
    move-object v5, v4

    :goto_1c
    if-eqz v2, :cond_25

    iget-object v2, v2, Llyiahf/vczjk/y46;->OooO00o:Llyiahf/vczjk/x46;

    goto :goto_1d

    :cond_25
    move-object v2, v4

    :goto_1d
    sget-object v6, Llyiahf/vczjk/x46;->OooOOOO:Llyiahf/vczjk/x46;

    if-eq v2, v6, :cond_27

    if-eqz v16, :cond_26

    if-eqz v1, :cond_26

    iget-boolean v1, v1, Llyiahf/vczjk/g64;->OooO0OO:Z

    const/4 v2, 0x1

    if-ne v1, v2, :cond_26

    goto :goto_1e

    :cond_26
    const/4 v1, 0x0

    goto :goto_1f

    :cond_27
    :goto_1e
    const/4 v1, 0x1

    :goto_1f
    if-eqz v17, :cond_28

    invoke-static/range {v17 .. v17}, Llyiahf/vczjk/bv0;->OooO0OO(Llyiahf/vczjk/t4a;)Llyiahf/vczjk/y46;

    move-result-object v2

    if-eqz v2, :cond_28

    sget-object v6, Llyiahf/vczjk/x46;->OooOOO:Llyiahf/vczjk/x46;

    iget-object v11, v2, Llyiahf/vczjk/y46;->OooO00o:Llyiahf/vczjk/x46;

    if-ne v11, v6, :cond_29

    sget-object v6, Llyiahf/vczjk/x46;->OooOOO0:Llyiahf/vczjk/x46;

    const/4 v11, 0x0

    invoke-static {v2, v6, v11, v3}, Llyiahf/vczjk/y46;->OooO00o(Llyiahf/vczjk/y46;Llyiahf/vczjk/x46;ZI)Llyiahf/vczjk/y46;

    move-result-object v2

    goto :goto_20

    :cond_28
    move-object v2, v4

    :cond_29
    :goto_20
    if-nez v2, :cond_2a

    goto :goto_22

    :cond_2a
    if-nez v5, :cond_2b

    goto :goto_21

    :cond_2b
    iget-boolean v3, v5, Llyiahf/vczjk/y46;->OooO0O0:Z

    iget-boolean v6, v2, Llyiahf/vczjk/y46;->OooO0O0:Z

    if-eqz v6, :cond_2c

    if-nez v3, :cond_2c

    goto :goto_22

    :cond_2c
    if-nez v6, :cond_2d

    if-eqz v3, :cond_2d

    goto :goto_21

    :cond_2d
    iget-object v3, v2, Llyiahf/vczjk/y46;->OooO00o:Llyiahf/vczjk/x46;

    iget-object v6, v5, Llyiahf/vczjk/y46;->OooO00o:Llyiahf/vczjk/x46;

    invoke-virtual {v3, v6}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    move-result v11

    if-gez v11, :cond_2e

    goto :goto_22

    :cond_2e
    invoke-virtual {v3, v6}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    move-result v3

    if-lez v3, :cond_2f

    :goto_21
    move-object v5, v2

    :cond_2f
    :goto_22
    new-instance v3, Llyiahf/vczjk/f74;

    if-eqz v5, :cond_30

    iget-object v2, v5, Llyiahf/vczjk/y46;->OooO00o:Llyiahf/vczjk/x46;

    goto :goto_23

    :cond_30
    move-object v2, v4

    :goto_23
    if-eqz v5, :cond_31

    iget-boolean v5, v5, Llyiahf/vczjk/y46;->OooO0O0:Z

    const/4 v6, 0x1

    if-ne v5, v6, :cond_31

    const/4 v5, 0x1

    goto :goto_24

    :cond_31
    const/4 v5, 0x0

    :goto_24
    invoke-direct {v3, v2, v14, v1, v5}, Llyiahf/vczjk/f74;-><init>(Llyiahf/vczjk/x46;Llyiahf/vczjk/dr5;ZZ)V

    :goto_25
    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual/range {v23 .. v23}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :cond_32
    :goto_26
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_3b

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/util/List;

    invoke-static {v10, v5}, Llyiahf/vczjk/d21;->o00oO0o(ILjava/util/List;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/o0O00o0;

    if-eqz v5, :cond_3a

    iget-object v5, v5, Llyiahf/vczjk/o0O00o0;->OooO00o:Llyiahf/vczjk/yk4;

    if-eqz v5, :cond_3a

    invoke-static {v5}, Llyiahf/vczjk/bv0;->OooO0o(Llyiahf/vczjk/yk4;)Llyiahf/vczjk/x46;

    move-result-object v6

    if-nez v6, :cond_34

    move-object v11, v5

    check-cast v11, Llyiahf/vczjk/uk4;

    invoke-static {v11}, Llyiahf/vczjk/qu6;->OooO0oO(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/uk4;

    move-result-object v11

    if-eqz v11, :cond_33

    invoke-static {v11}, Llyiahf/vczjk/bv0;->OooO0o(Llyiahf/vczjk/yk4;)Llyiahf/vczjk/x46;

    move-result-object v11

    goto :goto_27

    :cond_33
    move-object v11, v4

    goto :goto_27

    :cond_34
    move-object v11, v6

    :goto_27
    sget-object v12, Llyiahf/vczjk/w64;->OooO00o:Ljava/lang/String;

    invoke-virtual {v13, v5}, Llyiahf/vczjk/uk2;->o00Ooo(Llyiahf/vczjk/yk4;)Llyiahf/vczjk/dp8;

    move-result-object v12

    invoke-static {v12}, Llyiahf/vczjk/bv0;->OooO0o0(Llyiahf/vczjk/dp8;)Llyiahf/vczjk/ic3;

    move-result-object v12

    sget-object v14, Llyiahf/vczjk/w64;->OooOO0O:Ljava/util/HashMap;

    invoke-virtual {v14, v12}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    move-result v12

    if-eqz v12, :cond_35

    sget-object v12, Llyiahf/vczjk/dr5;->OooOOO0:Llyiahf/vczjk/dr5;

    goto :goto_28

    :cond_35
    invoke-virtual {v13, v5}, Llyiahf/vczjk/uk2;->OooO0oO(Llyiahf/vczjk/yk4;)Llyiahf/vczjk/dp8;

    move-result-object v12

    invoke-static {v12}, Llyiahf/vczjk/bv0;->OooO0o0(Llyiahf/vczjk/dp8;)Llyiahf/vczjk/ic3;

    move-result-object v12

    sget-object v14, Llyiahf/vczjk/w64;->OooOO0:Ljava/util/HashMap;

    invoke-virtual {v14, v12}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    move-result v12

    if-eqz v12, :cond_36

    sget-object v12, Llyiahf/vczjk/dr5;->OooOOO:Llyiahf/vczjk/dr5;

    goto :goto_28

    :cond_36
    move-object v12, v4

    :goto_28
    invoke-virtual {v13, v5}, Llyiahf/vczjk/uk2;->Oooo0o0(Llyiahf/vczjk/yk4;)Z

    move-result v14

    if-nez v14, :cond_38

    check-cast v5, Llyiahf/vczjk/uk4;

    invoke-virtual {v5}, Llyiahf/vczjk/uk4;->o00000O()Llyiahf/vczjk/iaa;

    move-result-object v5

    instance-of v5, v5, Llyiahf/vczjk/v26;

    if-eqz v5, :cond_37

    goto :goto_29

    :cond_37
    const/4 v5, 0x0

    goto :goto_2a

    :cond_38
    :goto_29
    const/4 v5, 0x1

    :goto_2a
    new-instance v14, Llyiahf/vczjk/f74;

    if-eq v11, v6, :cond_39

    const/4 v6, 0x1

    goto :goto_2b

    :cond_39
    const/4 v6, 0x0

    :goto_2b
    invoke-direct {v14, v11, v12, v5, v6}, Llyiahf/vczjk/f74;-><init>(Llyiahf/vczjk/x46;Llyiahf/vczjk/dr5;ZZ)V

    goto :goto_2c

    :cond_3a
    move-object v14, v4

    :goto_2c
    if-eqz v14, :cond_32

    invoke-virtual {v1, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_26

    :cond_3b
    if-nez v10, :cond_3c

    if-eqz v8, :cond_3c

    const/4 v2, 0x1

    goto :goto_2d

    :cond_3c
    const/4 v2, 0x0

    :goto_2d
    if-nez v10, :cond_3d

    instance-of v5, v15, Llyiahf/vczjk/tca;

    if-eqz v5, :cond_3d

    check-cast v15, Llyiahf/vczjk/tca;

    iget-object v5, v15, Llyiahf/vczjk/tca;->OooOoO0:Llyiahf/vczjk/uk4;

    if-eqz v5, :cond_3d

    const/4 v5, 0x1

    goto :goto_2e

    :cond_3d
    const/4 v5, 0x0

    :goto_2e
    new-instance v6, Ljava/util/ArrayList;

    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v11

    :cond_3e
    :goto_2f
    invoke-interface {v11}, Ljava/util/Iterator;->hasNext()Z

    move-result v12

    if-eqz v12, :cond_40

    invoke-interface {v11}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v12

    check-cast v12, Llyiahf/vczjk/f74;

    iget-boolean v13, v12, Llyiahf/vczjk/f74;->OooO0Oo:Z

    if-eqz v13, :cond_3f

    move-object v12, v4

    goto :goto_30

    :cond_3f
    iget-object v12, v12, Llyiahf/vczjk/f74;->OooO00o:Llyiahf/vczjk/x46;

    :goto_30
    if-eqz v12, :cond_3e

    invoke-virtual {v6, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_2f

    :cond_40
    invoke-static {v6}, Llyiahf/vczjk/d21;->o0000OOo(Ljava/lang/Iterable;)Ljava/util/Set;

    move-result-object v6

    iget-boolean v11, v3, Llyiahf/vczjk/f74;->OooO0Oo:Z

    iget-object v12, v3, Llyiahf/vczjk/f74;->OooO00o:Llyiahf/vczjk/x46;

    if-eqz v11, :cond_41

    move-object v13, v4

    goto :goto_31

    :cond_41
    move-object v13, v12

    :goto_31
    sget-object v14, Llyiahf/vczjk/x46;->OooOOO0:Llyiahf/vczjk/x46;

    if-ne v13, v14, :cond_42

    goto :goto_32

    :cond_42
    sget-object v14, Llyiahf/vczjk/x46;->OooOOOO:Llyiahf/vczjk/x46;

    sget-object v15, Llyiahf/vczjk/x46;->OooOOO:Llyiahf/vczjk/x46;

    invoke-static {v6, v14, v15, v13, v2}, Llyiahf/vczjk/xr6;->OooOOoo(Ljava/util/Set;Ljava/lang/Enum;Ljava/lang/Enum;Ljava/lang/Enum;Z)Ljava/lang/Object;

    move-result-object v6

    move-object v14, v6

    check-cast v14, Llyiahf/vczjk/x46;

    :goto_32
    if-nez v14, :cond_46

    new-instance v6, Ljava/util/ArrayList;

    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v13

    :cond_43
    :goto_33
    invoke-interface {v13}, Ljava/util/Iterator;->hasNext()Z

    move-result v15

    if-eqz v15, :cond_44

    invoke-interface {v13}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v15

    check-cast v15, Llyiahf/vczjk/f74;

    iget-object v15, v15, Llyiahf/vczjk/f74;->OooO00o:Llyiahf/vczjk/x46;

    if-eqz v15, :cond_43

    invoke-virtual {v6, v15}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_33

    :cond_44
    invoke-static {v6}, Llyiahf/vczjk/d21;->o0000OOo(Ljava/lang/Iterable;)Ljava/util/Set;

    move-result-object v6

    sget-object v13, Llyiahf/vczjk/x46;->OooOOO0:Llyiahf/vczjk/x46;

    if-ne v12, v13, :cond_45

    goto :goto_34

    :cond_45
    sget-object v13, Llyiahf/vczjk/x46;->OooOOOO:Llyiahf/vczjk/x46;

    sget-object v15, Llyiahf/vczjk/x46;->OooOOO:Llyiahf/vczjk/x46;

    invoke-static {v6, v13, v15, v12, v2}, Llyiahf/vczjk/xr6;->OooOOoo(Ljava/util/Set;Ljava/lang/Enum;Ljava/lang/Enum;Ljava/lang/Enum;Z)Ljava/lang/Object;

    move-result-object v6

    move-object v13, v6

    check-cast v13, Llyiahf/vczjk/x46;

    goto :goto_34

    :cond_46
    move-object v13, v14

    :goto_34
    new-instance v6, Ljava/util/ArrayList;

    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v12

    :cond_47
    :goto_35
    invoke-interface {v12}, Ljava/util/Iterator;->hasNext()Z

    move-result v15

    if-eqz v15, :cond_48

    invoke-interface {v12}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v15

    check-cast v15, Llyiahf/vczjk/f74;

    iget-object v15, v15, Llyiahf/vczjk/f74;->OooO0O0:Llyiahf/vczjk/dr5;

    if-eqz v15, :cond_47

    invoke-virtual {v6, v15}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_35

    :cond_48
    invoke-static {v6}, Llyiahf/vczjk/d21;->o0000OOo(Ljava/lang/Iterable;)Ljava/util/Set;

    move-result-object v6

    sget-object v12, Llyiahf/vczjk/dr5;->OooOOO:Llyiahf/vczjk/dr5;

    sget-object v15, Llyiahf/vczjk/dr5;->OooOOO0:Llyiahf/vczjk/dr5;

    iget-object v4, v3, Llyiahf/vczjk/f74;->OooO0O0:Llyiahf/vczjk/dr5;

    invoke-static {v6, v12, v15, v4, v2}, Llyiahf/vczjk/xr6;->OooOOoo(Ljava/util/Set;Ljava/lang/Enum;Ljava/lang/Enum;Ljava/lang/Enum;Z)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/dr5;

    if-eqz v13, :cond_49

    if-nez p5, :cond_49

    if-eqz v5, :cond_4a

    sget-object v4, Llyiahf/vczjk/x46;->OooOOO:Llyiahf/vczjk/x46;

    if-ne v13, v4, :cond_4a

    :cond_49
    const/4 v13, 0x0

    :cond_4a
    if-eqz v13, :cond_4b

    if-nez v14, :cond_4b

    const/4 v4, 0x1

    goto :goto_36

    :cond_4b
    const/4 v4, 0x0

    :goto_36
    sget-object v5, Llyiahf/vczjk/x46;->OooOOOO:Llyiahf/vczjk/x46;

    if-ne v13, v5, :cond_4f

    if-ne v11, v4, :cond_4c

    iget-boolean v3, v3, Llyiahf/vczjk/f74;->OooO0OO:Z

    if-eqz v3, :cond_4c

    goto :goto_37

    :cond_4c
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v3

    if-eqz v3, :cond_4d

    goto :goto_38

    :cond_4d
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_4e
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_4f

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/f74;

    iget-boolean v5, v3, Llyiahf/vczjk/f74;->OooO0Oo:Z

    if-ne v5, v4, :cond_4e

    iget-boolean v3, v3, Llyiahf/vczjk/f74;->OooO0OO:Z

    if-eqz v3, :cond_4e

    :goto_37
    const/4 v3, 0x1

    goto :goto_39

    :cond_4f
    :goto_38
    const/4 v3, 0x0

    :goto_39
    new-instance v1, Llyiahf/vczjk/f74;

    invoke-direct {v1, v13, v2, v3, v4}, Llyiahf/vczjk/f74;-><init>(Llyiahf/vczjk/x46;Llyiahf/vczjk/dr5;ZZ)V

    aput-object v1, v9, v10

    const/4 v1, 0x1

    add-int/2addr v10, v1

    move-object/from16 v1, p2

    move-object/from16 v4, v21

    move-object/from16 v6, v22

    move-object/from16 v5, v23

    goto/16 :goto_3

    :cond_50
    const/4 v1, 0x1

    new-instance v2, Llyiahf/vczjk/o0oOO;

    move-object/from16 v3, p4

    invoke-direct {v2, v1, v3, v9}, Llyiahf/vczjk/o0oOO;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual/range {p2 .. p2}, Llyiahf/vczjk/uk4;->o00000O()Llyiahf/vczjk/iaa;

    move-result-object v1

    iget-boolean v0, v0, Llyiahf/vczjk/bv0;->OooO0O0:Z

    const/4 v11, 0x0

    invoke-static {v1, v2, v11, v0}, Llyiahf/vczjk/tp3;->OooOO0o(Llyiahf/vczjk/iaa;Llyiahf/vczjk/o0oOO;IZ)Llyiahf/vczjk/w3;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/w3;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/iaa;

    return-object v0
.end method

.method public OooO0Oo(Llyiahf/vczjk/h37;)V
    .locals 0

    return-void
.end method

.method public OooO0o(Llyiahf/vczjk/by0;Llyiahf/vczjk/u82;)Z
    .locals 0

    const-string p2, "classDescriptor"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 p1, 0x1

    return p1
.end method

.method public OooO0o0(Llyiahf/vczjk/sg5;Z)V
    .locals 0

    return-void
.end method

.method public OooO0oO(Ljava/lang/Object;)Ljava/lang/Iterable;
    .locals 0

    check-cast p1, Llyiahf/vczjk/eo0;

    if-eqz p1, :cond_0

    invoke-interface {p1}, Llyiahf/vczjk/eo0;->OooOOO0()Ljava/util/Collection;

    move-result-object p1

    if-eqz p1, :cond_0

    check-cast p1, Ljava/lang/Iterable;

    return-object p1

    :cond_0
    sget-object p1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object p1
.end method

.method public OooO0oo(Llyiahf/vczjk/hd7;Ljava/lang/String;Llyiahf/vczjk/dp8;Llyiahf/vczjk/dp8;)Llyiahf/vczjk/uk4;
    .locals 1

    const-string v0, "proto"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "flexibleId"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "lowerBound"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "upperBound"

    invoke-static {p4, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "kotlin.jvm.PlatformType"

    invoke-virtual {p2, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_0

    sget-object p1, Llyiahf/vczjk/tq2;->OooOo0o:Llyiahf/vczjk/tq2;

    invoke-virtual {p3}, Llyiahf/vczjk/dp8;->toString()Ljava/lang/String;

    move-result-object p3

    invoke-virtual {p4}, Llyiahf/vczjk/dp8;->toString()Ljava/lang/String;

    move-result-object p4

    filled-new-array {p2, p3, p4}, [Ljava/lang/String;

    move-result-object p2

    invoke-static {p1, p2}, Llyiahf/vczjk/uq2;->OooO0OO(Llyiahf/vczjk/tq2;[Ljava/lang/String;)Llyiahf/vczjk/rq2;

    move-result-object p1

    return-object p1

    :cond_0
    sget-object p2, Llyiahf/vczjk/ue4;->OooO0oO:Llyiahf/vczjk/ug3;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/sg3;->OooOO0(Llyiahf/vczjk/ug3;)Z

    move-result p1

    if-eqz p1, :cond_1

    new-instance p1, Llyiahf/vczjk/qg7;

    invoke-direct {p1, p3, p4}, Llyiahf/vczjk/qg7;-><init>(Llyiahf/vczjk/dp8;Llyiahf/vczjk/dp8;)V

    return-object p1

    :cond_1
    invoke-static {p3, p4}, Llyiahf/vczjk/so8;->OooOoOO(Llyiahf/vczjk/dp8;Llyiahf/vczjk/dp8;)Llyiahf/vczjk/iaa;

    move-result-object p1

    return-object p1
.end method

.method public OooOO0O(Landroid/app/Application;)Ljava/util/Comparator;
    .locals 1

    new-instance p1, Llyiahf/vczjk/h93;

    const/16 v0, 0x18

    invoke-direct {p1, v0}, Llyiahf/vczjk/h93;-><init>(I)V

    return-object p1
.end method

.method public OooOOO(Llyiahf/vczjk/rb4;F)Ljava/lang/Object;
    .locals 4

    invoke-virtual {p1}, Llyiahf/vczjk/rb4;->OoooOoo()I

    move-result v0

    const/4 v1, 0x1

    if-ne v0, v1, :cond_0

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    :goto_0
    if-eqz v1, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/rb4;->OooO0Oo()V

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/rb4;->Oooo0oO()D

    move-result-wide v2

    double-to-float v0, v2

    invoke-virtual {p1}, Llyiahf/vczjk/rb4;->Oooo0oO()D

    move-result-wide v2

    double-to-float v2, v2

    :goto_1
    invoke-virtual {p1}, Llyiahf/vczjk/rb4;->OooOoOO()Z

    move-result v3

    if-eqz v3, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/rb4;->o0ooOO0()V

    goto :goto_1

    :cond_2
    if-eqz v1, :cond_3

    invoke-virtual {p1}, Llyiahf/vczjk/rb4;->OooOOOO()V

    :cond_3
    new-instance p1, Llyiahf/vczjk/u78;

    const/high16 v1, 0x42c80000    # 100.0f

    div-float/2addr v0, v1

    mul-float/2addr v0, p2

    div-float/2addr v2, v1

    mul-float/2addr v2, p2

    invoke-direct {p1, v0, v2}, Llyiahf/vczjk/u78;-><init>(FF)V

    return-object p1
.end method

.method public OooOOO0(Llyiahf/vczjk/ld9;Ljava/util/Collection;)Ljava/util/ArrayList;
    .locals 23

    move-object/from16 v0, p1

    const-string v1, "c"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Iterable;

    new-instance v2, Ljava/util/ArrayList;

    const/16 v3, 0xa

    invoke-static {v1, v3}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v4

    invoke-direct {v2, v4}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_2f

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/eo0;

    instance-of v5, v4, Llyiahf/vczjk/d64;

    if-nez v5, :cond_0

    :goto_1
    move v8, v3

    goto/16 :goto_21

    :cond_0
    invoke-interface {v4}, Llyiahf/vczjk/eo0;->getKind()I

    move-result v5

    const/4 v6, 0x2

    const/4 v7, 0x1

    if-ne v5, v6, :cond_1

    invoke-interface {v4}, Llyiahf/vczjk/eo0;->OooO00o()Llyiahf/vczjk/eo0;

    move-result-object v5

    invoke-interface {v5}, Llyiahf/vczjk/eo0;->OooOOO0()Ljava/util/Collection;

    move-result-object v5

    invoke-interface {v5}, Ljava/util/Collection;->size()I

    move-result v5

    if-ne v5, v7, :cond_1

    goto :goto_1

    :cond_1
    invoke-static {v4}, Llyiahf/vczjk/l4a;->OooOoo0(Llyiahf/vczjk/v02;)Llyiahf/vczjk/gz0;

    move-result-object v5

    if-nez v5, :cond_2

    move-object v5, v4

    check-cast v5, Llyiahf/vczjk/l21;

    invoke-virtual {v5}, Llyiahf/vczjk/l21;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v5

    goto :goto_6

    :cond_2
    instance-of v8, v5, Llyiahf/vczjk/nr4;

    if-eqz v8, :cond_3

    check-cast v5, Llyiahf/vczjk/nr4;

    goto :goto_2

    :cond_3
    const/4 v5, 0x0

    :goto_2
    if-eqz v5, :cond_4

    iget-object v5, v5, Llyiahf/vczjk/nr4;->OooOo0o:Llyiahf/vczjk/sc9;

    invoke-virtual {v5}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/util/List;

    goto :goto_3

    :cond_4
    const/4 v5, 0x0

    :goto_3
    if-eqz v5, :cond_8

    invoke-interface {v5}, Ljava/util/Collection;->isEmpty()Z

    move-result v8

    if-eqz v8, :cond_5

    goto :goto_5

    :cond_5
    new-instance v8, Ljava/util/ArrayList;

    invoke-static {v5, v3}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v9

    invoke-direct {v8, v9}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v5

    :goto_4
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v9

    if-eqz v9, :cond_6

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/sl7;

    new-instance v10, Llyiahf/vczjk/kr4;

    invoke-direct {v10, v9, v0, v7}, Llyiahf/vczjk/kr4;-><init>(Llyiahf/vczjk/sl7;Llyiahf/vczjk/ld9;Z)V

    invoke-virtual {v8, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_4

    :cond_6
    move-object v5, v4

    check-cast v5, Llyiahf/vczjk/l21;

    invoke-virtual {v5}, Llyiahf/vczjk/l21;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v5

    invoke-static {v5, v8}, Llyiahf/vczjk/d21;->o000000o(Ljava/lang/Iterable;Ljava/lang/Iterable;)Ljava/util/ArrayList;

    move-result-object v5

    invoke-virtual {v5}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v8

    if-eqz v8, :cond_7

    sget-object v5, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    goto :goto_6

    :cond_7
    new-instance v8, Llyiahf/vczjk/po;

    const/4 v9, 0x0

    invoke-direct {v8, v9, v5}, Llyiahf/vczjk/po;-><init>(ILjava/util/List;)V

    move-object v5, v8

    goto :goto_6

    :cond_8
    :goto_5
    move-object v5, v4

    check-cast v5, Llyiahf/vczjk/l21;

    invoke-virtual {v5}, Llyiahf/vczjk/l21;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v5

    :goto_6
    invoke-static {v0, v5}, Llyiahf/vczjk/l4a;->OooOOo(Llyiahf/vczjk/ld9;Llyiahf/vczjk/ko;)Llyiahf/vczjk/ld9;

    move-result-object v12

    instance-of v5, v4, Llyiahf/vczjk/r64;

    if-eqz v5, :cond_9

    move-object v5, v4

    check-cast v5, Llyiahf/vczjk/ua7;

    iget-object v5, v5, Llyiahf/vczjk/ua7;->Oooo0o0:Llyiahf/vczjk/va7;

    if-eqz v5, :cond_9

    iget-boolean v8, v5, Llyiahf/vczjk/la7;->OooOo00:Z

    if-nez v8, :cond_9

    move-object v10, v5

    goto :goto_7

    :cond_9
    move-object v10, v4

    :goto_7
    invoke-interface {v4}, Llyiahf/vczjk/co0;->Ooooooo()Llyiahf/vczjk/mp4;

    move-result-object v5

    if-eqz v5, :cond_d

    instance-of v5, v10, Llyiahf/vczjk/rf3;

    if-eqz v5, :cond_a

    move-object v5, v10

    check-cast v5, Llyiahf/vczjk/rf3;

    goto :goto_8

    :cond_a
    const/4 v5, 0x0

    :goto_8
    if-eqz v5, :cond_b

    sget-object v8, Llyiahf/vczjk/o64;->OoooOO0:Llyiahf/vczjk/k82;

    invoke-interface {v5, v8}, Llyiahf/vczjk/co0;->Oooo0o0(Llyiahf/vczjk/k82;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/tca;

    move-object v15, v5

    goto :goto_9

    :cond_b
    const/4 v15, 0x0

    :goto_9
    sget-object v21, Llyiahf/vczjk/iu6;->OooOoo0:Llyiahf/vczjk/iu6;

    move-object v14, v4

    check-cast v14, Llyiahf/vczjk/d64;

    if-eqz v15, :cond_c

    move-object v5, v15

    check-cast v5, Llyiahf/vczjk/l21;

    invoke-virtual {v5}, Llyiahf/vczjk/l21;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v5

    invoke-static {v12, v5}, Llyiahf/vczjk/l4a;->OooOOo(Llyiahf/vczjk/ld9;Llyiahf/vczjk/ko;)Llyiahf/vczjk/ld9;

    move-result-object v5

    move-object/from16 v17, v5

    goto :goto_a

    :cond_c
    move-object/from16 v17, v12

    :goto_a
    sget-object v18, Llyiahf/vczjk/bo;->OooOOO:Llyiahf/vczjk/bo;

    const/16 v16, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    move-object/from16 v13, p0

    invoke-virtual/range {v13 .. v21}, Llyiahf/vczjk/tp3;->OooO(Llyiahf/vczjk/d64;Llyiahf/vczjk/co0;ZLlyiahf/vczjk/ld9;Llyiahf/vczjk/bo;Llyiahf/vczjk/x3a;ZLlyiahf/vczjk/oe3;)Llyiahf/vczjk/uk4;

    move-result-object v5

    goto :goto_b

    :cond_d
    const/4 v5, 0x0

    :goto_b
    instance-of v8, v4, Llyiahf/vczjk/o64;

    if-eqz v8, :cond_e

    move-object v8, v4

    check-cast v8, Llyiahf/vczjk/o64;

    goto :goto_c

    :cond_e
    const/4 v8, 0x0

    :goto_c
    const/4 v9, 0x0

    if-eqz v8, :cond_12

    invoke-virtual {v8}, Llyiahf/vczjk/y02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v11

    const-string v13, "null cannot be cast to non-null type org.jetbrains.kotlin.descriptors.ClassDescriptor"

    invoke-static {v11, v13}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v11, Llyiahf/vczjk/by0;

    const/4 v13, 0x3

    invoke-static {v8, v13}, Llyiahf/vczjk/r02;->OooOO0(Llyiahf/vczjk/rf3;I)Ljava/lang/String;

    move-result-object v8

    invoke-static {v11, v8}, Llyiahf/vczjk/t51;->OoooOoO(Llyiahf/vczjk/by0;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v8

    if-eqz v8, :cond_12

    sget-object v11, Llyiahf/vczjk/a17;->OooO0Oo:Ljava/util/LinkedHashMap;

    invoke-virtual {v11, v8}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/b17;

    if-eqz v8, :cond_12

    iget-object v11, v8, Llyiahf/vczjk/b17;->OooO0OO:Ljava/lang/String;

    if-eqz v11, :cond_10

    const-string v13, "2."

    invoke-static {v11, v13, v9}, Llyiahf/vczjk/g79;->Oooo00o(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v13

    if-ne v13, v7, :cond_f

    goto :goto_d

    :cond_f
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "Check failed."

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_10
    :goto_d
    if-nez v11, :cond_11

    goto :goto_e

    :cond_11
    iget-object v8, v8, Llyiahf/vczjk/b17;->OooO0Oo:Llyiahf/vczjk/b17;

    goto :goto_e

    :cond_12
    const/4 v8, 0x0

    :goto_e
    if-eqz v8, :cond_13

    iget-object v11, v8, Llyiahf/vczjk/b17;->OooO0O0:Ljava/util/ArrayList;

    invoke-virtual {v11}, Ljava/util/ArrayList;->size()I

    move-object v11, v4

    check-cast v11, Llyiahf/vczjk/o64;

    invoke-virtual {v11}, Llyiahf/vczjk/tf3;->OoooOOO()Ljava/util/List;

    move-result-object v11

    invoke-interface {v11}, Ljava/util/List;->size()I

    :cond_13
    iget-object v11, v0, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v11, Llyiahf/vczjk/s64;

    const-string v13, "javaTypeEnhancementState"

    iget-object v11, v11, Llyiahf/vczjk/s64;->OooOo0O:Llyiahf/vczjk/c74;

    invoke-static {v11, v13}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v11, Llyiahf/vczjk/b74;->OooOOO:Llyiahf/vczjk/b74;

    sget-object v13, Llyiahf/vczjk/p64;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-virtual {v11, v13}, Llyiahf/vczjk/b74;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v11

    sget-object v13, Llyiahf/vczjk/yq7;->OooOOOO:Llyiahf/vczjk/yq7;

    if-ne v11, v13, :cond_14

    instance-of v11, v4, Llyiahf/vczjk/rf3;

    if-eqz v11, :cond_15

    sget-object v11, Llyiahf/vczjk/o64;->o000oOoO:Llyiahf/vczjk/k82;

    invoke-interface {v4, v11}, Llyiahf/vczjk/co0;->Oooo0o0(Llyiahf/vczjk/k82;)Ljava/lang/Object;

    move-result-object v11

    sget-object v13, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-static {v11, v13}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v11

    if-eqz v11, :cond_15

    move/from16 v20, v7

    goto :goto_f

    :cond_14
    iget-object v11, v12, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v11, Llyiahf/vczjk/s64;

    iget-object v11, v11, Llyiahf/vczjk/s64;->OooOo00:Llyiahf/vczjk/wp3;

    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_15
    move/from16 v20, v9

    :goto_f
    invoke-interface {v10}, Llyiahf/vczjk/co0;->OoooOOO()Ljava/util/List;

    move-result-object v11

    const-string v13, "getValueParameters(...)"

    invoke-static {v11, v13}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v14, Ljava/util/ArrayList;

    invoke-static {v11, v3}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v15

    invoke-direct {v14, v15}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v11}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v11

    :goto_10
    invoke-interface {v11}, Ljava/util/Iterator;->hasNext()Z

    move-result v15

    if-eqz v15, :cond_18

    invoke-interface {v11}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v15

    check-cast v15, Llyiahf/vczjk/tca;

    if-eqz v8, :cond_16

    iget-object v9, v8, Llyiahf/vczjk/b17;->OooO0O0:Ljava/util/ArrayList;

    iget v3, v15, Llyiahf/vczjk/tca;->OooOo0:I

    invoke-static {v3, v9}, Llyiahf/vczjk/d21;->o00oO0o(ILjava/util/List;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/x3a;

    move-object/from16 v19, v3

    goto :goto_11

    :cond_16
    const/16 v19, 0x0

    :goto_11
    new-instance v3, Llyiahf/vczjk/oo000o;

    const/16 v9, 0x18

    invoke-direct {v3, v15, v9}, Llyiahf/vczjk/oo000o;-><init>(Ljava/lang/Object;I)V

    move-object v9, v14

    move-object v14, v4

    check-cast v14, Llyiahf/vczjk/d64;

    if-eqz v15, :cond_17

    move-object/from16 v16, v15

    check-cast v16, Llyiahf/vczjk/l21;

    invoke-virtual/range {v16 .. v16}, Llyiahf/vczjk/l21;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v6

    invoke-static {v12, v6}, Llyiahf/vczjk/l4a;->OooOOo(Llyiahf/vczjk/ld9;Llyiahf/vczjk/ko;)Llyiahf/vczjk/ld9;

    move-result-object v6

    move-object/from16 v17, v6

    goto :goto_12

    :cond_17
    move-object/from16 v17, v12

    :goto_12
    sget-object v18, Llyiahf/vczjk/bo;->OooOOO:Llyiahf/vczjk/bo;

    const/16 v16, 0x0

    move-object/from16 v21, v3

    move-object v6, v9

    move-object v3, v13

    move-object/from16 v13, p0

    invoke-virtual/range {v13 .. v21}, Llyiahf/vczjk/tp3;->OooO(Llyiahf/vczjk/d64;Llyiahf/vczjk/co0;ZLlyiahf/vczjk/ld9;Llyiahf/vczjk/bo;Llyiahf/vczjk/x3a;ZLlyiahf/vczjk/oe3;)Llyiahf/vczjk/uk4;

    move-result-object v9

    invoke-virtual {v6, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move-object v13, v3

    move-object v14, v6

    const/16 v3, 0xa

    const/4 v9, 0x0

    goto :goto_10

    :cond_18
    move-object v3, v13

    move-object v6, v14

    instance-of v9, v4, Llyiahf/vczjk/sa7;

    if-eqz v9, :cond_19

    move-object v9, v4

    check-cast v9, Llyiahf/vczjk/sa7;

    goto :goto_13

    :cond_19
    const/4 v9, 0x0

    :goto_13
    if-eqz v9, :cond_1a

    invoke-static {v9}, Llyiahf/vczjk/c6a;->OooooOo(Llyiahf/vczjk/sa7;)Z

    move-result v9

    if-ne v9, v7, :cond_1a

    sget-object v9, Llyiahf/vczjk/bo;->OooOOOO:Llyiahf/vczjk/bo;

    :goto_14
    move-object v13, v9

    goto :goto_15

    :cond_1a
    sget-object v9, Llyiahf/vczjk/bo;->OooOOO0:Llyiahf/vczjk/bo;

    goto :goto_14

    :goto_15
    if-eqz v8, :cond_1b

    iget-object v8, v8, Llyiahf/vczjk/b17;->OooO00o:Llyiahf/vczjk/x3a;

    move-object v14, v8

    goto :goto_16

    :cond_1b
    const/4 v14, 0x0

    :goto_16
    sget-object v16, Llyiahf/vczjk/iu6;->OooOoo:Llyiahf/vczjk/iu6;

    const/4 v11, 0x1

    move-object v9, v4

    check-cast v9, Llyiahf/vczjk/d64;

    const/4 v15, 0x0

    const/16 v17, 0x0

    move-object/from16 v8, p0

    invoke-virtual/range {v8 .. v16}, Llyiahf/vczjk/tp3;->OooO(Llyiahf/vczjk/d64;Llyiahf/vczjk/co0;ZLlyiahf/vczjk/ld9;Llyiahf/vczjk/bo;Llyiahf/vczjk/x3a;ZLlyiahf/vczjk/oe3;)Llyiahf/vczjk/uk4;

    move-result-object v9

    invoke-interface {v4}, Llyiahf/vczjk/co0;->OooOOoo()Llyiahf/vczjk/uk4;

    move-result-object v8

    invoke-static {v8}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    sget-object v10, Llyiahf/vczjk/iu6;->OooOooo:Llyiahf/vczjk/iu6;

    const/4 v11, 0x0

    invoke-static {v8, v10, v11}, Llyiahf/vczjk/l5a;->OooO0OO(Llyiahf/vczjk/uk4;Llyiahf/vczjk/oe3;Llyiahf/vczjk/dt8;)Z

    move-result v8

    const-string v12, "getType(...)"

    if-nez v8, :cond_21

    invoke-interface {v4}, Llyiahf/vczjk/co0;->Ooooooo()Llyiahf/vczjk/mp4;

    move-result-object v8

    if-eqz v8, :cond_1c

    invoke-virtual {v8}, Llyiahf/vczjk/mp4;->getType()Llyiahf/vczjk/uk4;

    move-result-object v8

    invoke-static {v8, v10, v11}, Llyiahf/vczjk/l5a;->OooO0OO(Llyiahf/vczjk/uk4;Llyiahf/vczjk/oe3;Llyiahf/vczjk/dt8;)Z

    move-result v8

    goto :goto_17

    :cond_1c
    move/from16 v8, v17

    :goto_17
    if-nez v8, :cond_21

    invoke-interface {v4}, Llyiahf/vczjk/co0;->OoooOOO()Ljava/util/List;

    move-result-object v8

    invoke-static {v8, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v8}, Ljava/util/Collection;->isEmpty()Z

    move-result v3

    if-eqz v3, :cond_1e

    :cond_1d
    move/from16 v3, v17

    goto :goto_18

    :cond_1e
    invoke-interface {v8}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :cond_1f
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_1d

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/tca;

    check-cast v8, Llyiahf/vczjk/bda;

    invoke-virtual {v8}, Llyiahf/vczjk/bda;->getType()Llyiahf/vczjk/uk4;

    move-result-object v8

    invoke-static {v8, v12}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v11, 0x0

    invoke-static {v8, v10, v11}, Llyiahf/vczjk/l5a;->OooO0OO(Llyiahf/vczjk/uk4;Llyiahf/vczjk/oe3;Llyiahf/vczjk/dt8;)Z

    move-result v8

    if-eqz v8, :cond_1f

    move v3, v7

    :goto_18
    if-eqz v3, :cond_20

    goto :goto_19

    :cond_20
    move/from16 v3, v17

    goto :goto_1a

    :cond_21
    :goto_19
    move v3, v7

    :goto_1a
    if-eqz v3, :cond_22

    sget-object v3, Llyiahf/vczjk/e16;->OooO0O0:Llyiahf/vczjk/k82;

    new-instance v8, Llyiahf/vczjk/r62;

    invoke-direct {v8}, Ljava/lang/Object;-><init>()V

    new-instance v11, Llyiahf/vczjk/xn6;

    invoke-direct {v11, v3, v8}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    goto :goto_1b

    :cond_22
    const/4 v11, 0x0

    :goto_1b
    if-nez v5, :cond_28

    if-nez v9, :cond_28

    invoke-virtual {v6}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v3

    if-eqz v3, :cond_24

    :cond_23
    move/from16 v7, v17

    goto :goto_1d

    :cond_24
    invoke-virtual {v6}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :cond_25
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_23

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/uk4;

    if-eqz v8, :cond_26

    move v8, v7

    goto :goto_1c

    :cond_26
    move/from16 v8, v17

    :goto_1c
    if-eqz v8, :cond_25

    :goto_1d
    if-nez v7, :cond_28

    if-eqz v11, :cond_27

    goto :goto_1e

    :cond_27
    const/16 v8, 0xa

    goto :goto_21

    :cond_28
    :goto_1e
    move-object v3, v4

    check-cast v3, Llyiahf/vczjk/d64;

    if-nez v5, :cond_2a

    invoke-interface {v4}, Llyiahf/vczjk/co0;->Ooooooo()Llyiahf/vczjk/mp4;

    move-result-object v5

    if-eqz v5, :cond_29

    invoke-virtual {v5}, Llyiahf/vczjk/mp4;->getType()Llyiahf/vczjk/uk4;

    move-result-object v5

    goto :goto_1f

    :cond_29
    const/4 v5, 0x0

    :cond_2a
    :goto_1f
    new-instance v7, Ljava/util/ArrayList;

    const/16 v8, 0xa

    invoke-static {v6, v8}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v10

    invoke-direct {v7, v10}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v6}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v6

    move/from16 v10, v17

    :goto_20
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    move-result v13

    if-eqz v13, :cond_2d

    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v13

    add-int/lit8 v14, v10, 0x1

    if-ltz v10, :cond_2c

    check-cast v13, Llyiahf/vczjk/uk4;

    if-nez v13, :cond_2b

    invoke-interface {v4}, Llyiahf/vczjk/co0;->OoooOOO()Ljava/util/List;

    move-result-object v13

    invoke-interface {v13, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/tca;

    check-cast v10, Llyiahf/vczjk/bda;

    invoke-virtual {v10}, Llyiahf/vczjk/bda;->getType()Llyiahf/vczjk/uk4;

    move-result-object v13

    invoke-static {v13, v12}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    :cond_2b
    invoke-virtual {v7, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move v10, v14

    goto :goto_20

    :cond_2c
    invoke-static {}, Llyiahf/vczjk/e21;->OoooOO0()V

    const/16 v22, 0x0

    throw v22

    :cond_2d
    if-nez v9, :cond_2e

    invoke-interface {v4}, Llyiahf/vczjk/co0;->OooOOoo()Llyiahf/vczjk/uk4;

    move-result-object v9

    invoke-static {v9}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    :cond_2e
    invoke-interface {v3, v5, v7, v9, v11}, Llyiahf/vczjk/d64;->oo000o(Llyiahf/vczjk/uk4;Ljava/util/ArrayList;Llyiahf/vczjk/uk4;Llyiahf/vczjk/xn6;)Llyiahf/vczjk/d64;

    move-result-object v4

    :goto_21
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move v3, v8

    goto/16 :goto_0

    :cond_2f
    return-object v2
.end method

.method public OooOOOO(Llyiahf/vczjk/pb7;Llyiahf/vczjk/d3a;ZIZ)Llyiahf/vczjk/dp8;
    .locals 8

    new-instance v0, Llyiahf/vczjk/f19;

    sget-object v1, Llyiahf/vczjk/cda;->OooOOO0:Llyiahf/vczjk/cda;

    iget-object v2, p1, Llyiahf/vczjk/pb7;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/a3a;

    move-object v3, v2

    check-cast v3, Llyiahf/vczjk/v82;

    invoke-virtual {v3}, Llyiahf/vczjk/v82;->o000OO()Llyiahf/vczjk/dp8;

    move-result-object v3

    invoke-direct {v0, v3, v1}, Llyiahf/vczjk/f19;-><init>(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)V

    const/4 v1, 0x0

    invoke-virtual {p0, v0, p1, v1, p4}, Llyiahf/vczjk/tp3;->OooOOOo(Llyiahf/vczjk/z4a;Llyiahf/vczjk/pb7;Llyiahf/vczjk/t4a;I)Llyiahf/vczjk/z4a;

    move-result-object p4

    invoke-virtual {p4}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object v0

    const-string v3, "getType(...)"

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/vt6;->OooOOOO(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/dp8;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/jp8;->OooOooO(Llyiahf/vczjk/uk4;)Z

    move-result v3

    if-eqz v3, :cond_0

    return-object v0

    :cond_0
    invoke-virtual {p4}, Llyiahf/vczjk/z4a;->OooO00o()Llyiahf/vczjk/cda;

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object p4

    invoke-static {p2}, Llyiahf/vczjk/ro;->OooO00o(Llyiahf/vczjk/d3a;)Llyiahf/vczjk/ko;

    move-result-object v3

    invoke-virtual {p0, p4, v3}, Llyiahf/vczjk/tp3;->OooO0O0(Llyiahf/vczjk/ko;Llyiahf/vczjk/ko;)V

    invoke-static {v0}, Llyiahf/vczjk/jp8;->OooOooO(Llyiahf/vczjk/uk4;)Z

    move-result p4

    if-eqz p4, :cond_1

    goto/16 :goto_4

    :cond_1
    invoke-static {v0}, Llyiahf/vczjk/jp8;->OooOooO(Llyiahf/vczjk/uk4;)Z

    move-result p4

    if-eqz p4, :cond_2

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o0OOO0o()Llyiahf/vczjk/d3a;

    move-result-object p4

    goto/16 :goto_3

    :cond_2
    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o0OOO0o()Llyiahf/vczjk/d3a;

    move-result-object p4

    const-string v3, "other"

    invoke-static {p4, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p2}, Llyiahf/vczjk/k10;->isEmpty()Z

    move-result v3

    if-eqz v3, :cond_3

    invoke-virtual {p4}, Llyiahf/vczjk/k10;->isEmpty()Z

    move-result v3

    if-eqz v3, :cond_3

    move-object p4, p2

    goto/16 :goto_3

    :cond_3
    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    sget-object v4, Llyiahf/vczjk/d3a;->OooOOO:Llyiahf/vczjk/xo8;

    iget-object v4, v4, Llyiahf/vczjk/xo8;->OooOOO0:Ljava/lang/Object;

    check-cast v4, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {v4}, Ljava/util/concurrent/ConcurrentHashMap;->values()Ljava/util/Collection;

    move-result-object v4

    const-string v5, "<get-values>(...)"

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v4}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :goto_0
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_8

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/lang/Number;

    invoke-virtual {v5}, Ljava/lang/Number;->intValue()I

    move-result v5

    iget-object v6, p2, Llyiahf/vczjk/k10;->OooOOO0:Llyiahf/vczjk/gy;

    invoke-virtual {v6, v5}, Llyiahf/vczjk/gy;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/qo;

    iget-object v7, p4, Llyiahf/vczjk/k10;->OooOOO0:Llyiahf/vczjk/gy;

    invoke-virtual {v7, v5}, Llyiahf/vczjk/gy;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/qo;

    if-nez v6, :cond_6

    if-eqz v5, :cond_5

    if-nez v6, :cond_4

    goto :goto_2

    :cond_4
    new-instance v7, Llyiahf/vczjk/qo;

    iget-object v5, v5, Llyiahf/vczjk/qo;->OooO00o:Llyiahf/vczjk/ko;

    iget-object v6, v6, Llyiahf/vczjk/qo;->OooO00o:Llyiahf/vczjk/ko;

    invoke-static {v5, v6}, Llyiahf/vczjk/yi4;->Oooo0OO(Llyiahf/vczjk/ko;Llyiahf/vczjk/ko;)Llyiahf/vczjk/ko;

    move-result-object v5

    invoke-direct {v7, v5}, Llyiahf/vczjk/qo;-><init>(Llyiahf/vczjk/ko;)V

    move-object v5, v7

    goto :goto_2

    :cond_5
    move-object v5, v1

    goto :goto_2

    :cond_6
    if-nez v5, :cond_7

    goto :goto_1

    :cond_7
    new-instance v7, Llyiahf/vczjk/qo;

    iget-object v6, v6, Llyiahf/vczjk/qo;->OooO00o:Llyiahf/vczjk/ko;

    iget-object v5, v5, Llyiahf/vczjk/qo;->OooO00o:Llyiahf/vczjk/ko;

    invoke-static {v6, v5}, Llyiahf/vczjk/yi4;->Oooo0OO(Llyiahf/vczjk/ko;Llyiahf/vczjk/ko;)Llyiahf/vczjk/ko;

    move-result-object v5

    invoke-direct {v7, v5}, Llyiahf/vczjk/qo;-><init>(Llyiahf/vczjk/ko;)V

    move-object v6, v7

    :goto_1
    move-object v5, v6

    :goto_2
    invoke-static {v3, v5}, Llyiahf/vczjk/t51;->OooOO0o(Ljava/util/AbstractCollection;Ljava/lang/Object;)V

    goto :goto_0

    :cond_8
    invoke-static {v3}, Llyiahf/vczjk/xo8;->OooO0o(Ljava/util/List;)Llyiahf/vczjk/d3a;

    move-result-object p4

    :goto_3
    const/4 v3, 0x1

    invoke-static {v0, v1, p4, v3}, Llyiahf/vczjk/vt6;->OooOooo(Llyiahf/vczjk/dp8;Ljava/util/List;Llyiahf/vczjk/d3a;I)Llyiahf/vczjk/dp8;

    move-result-object v0

    :goto_4
    invoke-static {v0, p3}, Llyiahf/vczjk/l5a;->OooO(Llyiahf/vczjk/dp8;Z)Llyiahf/vczjk/dp8;

    move-result-object p4

    if-eqz p5, :cond_9

    check-cast v2, Llyiahf/vczjk/v82;

    iget-object p5, v2, Llyiahf/vczjk/v82;->OooOo0o:Llyiahf/vczjk/o0O0o;

    const-string v0, "getTypeConstructor(...)"

    invoke-static {p5, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/ig5;->OooO0O0:Llyiahf/vczjk/ig5;

    iget-object p1, p1, Llyiahf/vczjk/pb7;->OooOOOo:Ljava/lang/Object;

    check-cast p1, Ljava/util/List;

    invoke-static {p1, v0, p2, p5, p3}, Llyiahf/vczjk/so8;->Oooo0oo(Ljava/util/List;Llyiahf/vczjk/jg5;Llyiahf/vczjk/d3a;Llyiahf/vczjk/n3a;Z)Llyiahf/vczjk/dp8;

    move-result-object p1

    invoke-static {p4, p1}, Llyiahf/vczjk/ll6;->OooOOo(Llyiahf/vczjk/dp8;Llyiahf/vczjk/dp8;)Llyiahf/vczjk/dp8;

    move-result-object p1

    return-object p1

    :cond_9
    return-object p4
.end method

.method public OooOOOo(Llyiahf/vczjk/z4a;Llyiahf/vczjk/pb7;Llyiahf/vczjk/t4a;I)Llyiahf/vczjk/z4a;
    .locals 10

    const/16 v0, 0x64

    iget-object v1, p2, Llyiahf/vczjk/pb7;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/a3a;

    if-gt p4, v0, :cond_1f

    invoke-virtual {p1}, Llyiahf/vczjk/z4a;->OooO0OO()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-static {p3}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {p3}, Llyiahf/vczjk/l5a;->OooOO0(Llyiahf/vczjk/t4a;)Llyiahf/vczjk/f19;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object v0

    const-string v2, "getType(...)"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v3

    const-string v4, "constructor"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v3}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v3

    instance-of v4, v3, Llyiahf/vczjk/t4a;

    const/4 v5, 0x0

    if-eqz v4, :cond_1

    iget-object v4, p2, Llyiahf/vczjk/pb7;->OooOOo0:Ljava/lang/Object;

    check-cast v4, Ljava/util/Map;

    invoke-interface {v4, v3}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/z4a;

    goto :goto_0

    :cond_1
    move-object v3, v5

    :goto_0
    if-nez v3, :cond_d

    invoke-virtual {p1}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object p3

    invoke-virtual {p3}, Llyiahf/vczjk/uk4;->o00000O()Llyiahf/vczjk/iaa;

    move-result-object p3

    invoke-static {p3}, Llyiahf/vczjk/vt6;->OooOOOO(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/dp8;

    move-result-object p3

    invoke-static {p3}, Llyiahf/vczjk/jp8;->OooOooO(Llyiahf/vczjk/uk4;)Z

    move-result v0

    if-nez v0, :cond_2

    sget-object v0, Llyiahf/vczjk/m5a;->OooOOOO:Llyiahf/vczjk/m5a;

    invoke-static {p3, v0, v5}, Llyiahf/vczjk/l5a;->OooO0OO(Llyiahf/vczjk/uk4;Llyiahf/vczjk/oe3;Llyiahf/vczjk/dt8;)Z

    move-result v0

    if-nez v0, :cond_3

    :cond_2
    :goto_1
    move-object v6, p0

    goto/16 :goto_5

    :cond_3
    invoke-virtual {p3}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v1

    invoke-interface {v0}, Llyiahf/vczjk/n3a;->OooO0OO()Ljava/util/List;

    move-result-object v3

    invoke-interface {v3}, Ljava/util/List;->size()I

    invoke-virtual {p3}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object v3

    invoke-interface {v3}, Ljava/util/List;->size()I

    instance-of v3, v1, Llyiahf/vczjk/t4a;

    if-eqz v3, :cond_4

    goto :goto_1

    :cond_4
    instance-of v3, v1, Llyiahf/vczjk/a3a;

    const/4 v4, 0x0

    if-eqz v3, :cond_9

    check-cast v1, Llyiahf/vczjk/a3a;

    invoke-virtual {p2, v1}, Llyiahf/vczjk/pb7;->OooOo0o(Llyiahf/vczjk/a3a;)Z

    move-result v2

    if-eqz v2, :cond_5

    new-instance p1, Llyiahf/vczjk/f19;

    sget-object p2, Llyiahf/vczjk/cda;->OooOOO0:Llyiahf/vczjk/cda;

    sget-object p3, Llyiahf/vczjk/tq2;->OooOOOo:Llyiahf/vczjk/tq2;

    check-cast v1, Llyiahf/vczjk/w02;

    invoke-virtual {v1}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object p4

    iget-object p4, p4, Llyiahf/vczjk/qt5;->OooOOO0:Ljava/lang/String;

    filled-new-array {p4}, [Ljava/lang/String;

    move-result-object p4

    invoke-static {p3, p4}, Llyiahf/vczjk/uq2;->OooO0OO(Llyiahf/vczjk/tq2;[Ljava/lang/String;)Llyiahf/vczjk/rq2;

    move-result-object p3

    invoke-direct {p1, p3, p2}, Llyiahf/vczjk/f19;-><init>(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)V

    return-object p1

    :cond_5
    invoke-virtual {p3}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object v2

    new-instance v3, Ljava/util/ArrayList;

    const/16 v6, 0xa

    invoke-static {v2, v6}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v7

    invoke-direct {v3, v7}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v7

    if-eqz v7, :cond_7

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v7

    add-int/lit8 v8, v4, 0x1

    if-ltz v4, :cond_6

    check-cast v7, Llyiahf/vczjk/z4a;

    invoke-interface {v0}, Llyiahf/vczjk/n3a;->OooO0OO()Ljava/util/List;

    move-result-object v9

    invoke-interface {v9, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/t4a;

    add-int/lit8 v9, p4, 0x1

    invoke-virtual {p0, v7, p2, v4, v9}, Llyiahf/vczjk/tp3;->OooOOOo(Llyiahf/vczjk/z4a;Llyiahf/vczjk/pb7;Llyiahf/vczjk/t4a;I)Llyiahf/vczjk/z4a;

    move-result-object v4

    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move v4, v8

    goto :goto_2

    :cond_6
    invoke-static {}, Llyiahf/vczjk/e21;->OoooOO0()V

    throw v5

    :cond_7
    move-object v0, v1

    check-cast v0, Llyiahf/vczjk/v82;

    iget-object v0, v0, Llyiahf/vczjk/v82;->OooOo0o:Llyiahf/vczjk/o0O0o;

    invoke-virtual {v0}, Llyiahf/vczjk/o0O0o;->OooO0OO()Ljava/util/List;

    move-result-object v0

    new-instance v2, Ljava/util/ArrayList;

    invoke-static {v0, v6}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v4

    invoke-direct {v2, v4}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_8

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/t4a;

    invoke-interface {v4}, Llyiahf/vczjk/t4a;->OooO00o()Llyiahf/vczjk/t4a;

    move-result-object v4

    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_3

    :cond_8
    invoke-static {v2, v3}, Llyiahf/vczjk/d21;->o0000Oo(Ljava/util/Collection;Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/lc5;->o0OOO0o(Ljava/util/List;)Ljava/util/Map;

    move-result-object v0

    new-instance v5, Llyiahf/vczjk/pb7;

    invoke-direct {v5, p2, v1, v3, v0}, Llyiahf/vczjk/pb7;-><init>(Llyiahf/vczjk/pb7;Llyiahf/vczjk/a3a;Ljava/util/List;Ljava/util/Map;)V

    invoke-virtual {p3}, Llyiahf/vczjk/uk4;->o0OOO0o()Llyiahf/vczjk/d3a;

    move-result-object v6

    invoke-virtual {p3}, Llyiahf/vczjk/uk4;->o000000o()Z

    move-result v7

    add-int/lit8 v8, p4, 0x1

    const/4 v9, 0x0

    move-object v4, p0

    invoke-virtual/range {v4 .. v9}, Llyiahf/vczjk/tp3;->OooOOOO(Llyiahf/vczjk/pb7;Llyiahf/vczjk/d3a;ZIZ)Llyiahf/vczjk/dp8;

    move-result-object v0

    move-object v6, v4

    invoke-virtual {p0, p3, p2, p4}, Llyiahf/vczjk/tp3;->OooOOo0(Llyiahf/vczjk/dp8;Llyiahf/vczjk/pb7;I)Llyiahf/vczjk/dp8;

    move-result-object p2

    invoke-static {v0, p2}, Llyiahf/vczjk/ll6;->OooOOo(Llyiahf/vczjk/dp8;Llyiahf/vczjk/dp8;)Llyiahf/vczjk/dp8;

    move-result-object p2

    new-instance p3, Llyiahf/vczjk/f19;

    invoke-virtual {p1}, Llyiahf/vczjk/z4a;->OooO00o()Llyiahf/vczjk/cda;

    move-result-object p1

    invoke-direct {p3, p2, p1}, Llyiahf/vczjk/f19;-><init>(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)V

    return-object p3

    :cond_9
    move-object v6, p0

    invoke-virtual {p0, p3, p2, p4}, Llyiahf/vczjk/tp3;->OooOOo0(Llyiahf/vczjk/dp8;Llyiahf/vczjk/pb7;I)Llyiahf/vczjk/dp8;

    move-result-object p2

    invoke-static {p2}, Llyiahf/vczjk/i5a;->OooO0Oo(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/i5a;

    invoke-virtual {p2}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object p4

    invoke-interface {p4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p4

    :goto_4
    invoke-interface {p4}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_c

    invoke-interface {p4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    add-int/lit8 v1, v4, 0x1

    if-ltz v4, :cond_b

    check-cast v0, Llyiahf/vczjk/z4a;

    invoke-virtual {v0}, Llyiahf/vczjk/z4a;->OooO0OO()Z

    move-result v3

    if-nez v3, :cond_a

    invoke-virtual {v0}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object v0

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v3, Llyiahf/vczjk/m5a;->OooOOO:Llyiahf/vczjk/m5a;

    invoke-static {v0, v3, v5}, Llyiahf/vczjk/l5a;->OooO0OO(Llyiahf/vczjk/uk4;Llyiahf/vczjk/oe3;Llyiahf/vczjk/dt8;)Z

    move-result v0

    if-nez v0, :cond_a

    invoke-virtual {p3}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object v0

    invoke-interface {v0, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/z4a;

    invoke-virtual {p3}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/n3a;->OooO0OO()Ljava/util/List;

    move-result-object v0

    invoke-interface {v0, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/t4a;

    :cond_a
    move v4, v1

    goto :goto_4

    :cond_b
    invoke-static {}, Llyiahf/vczjk/e21;->OoooOO0()V

    throw v5

    :cond_c
    new-instance p3, Llyiahf/vczjk/f19;

    invoke-virtual {p1}, Llyiahf/vczjk/z4a;->OooO00o()Llyiahf/vczjk/cda;

    move-result-object p1

    invoke-direct {p3, p2, p1}, Llyiahf/vczjk/f19;-><init>(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)V

    return-object p3

    :goto_5
    return-object p1

    :cond_d
    move-object v6, p0

    invoke-virtual {v3}, Llyiahf/vczjk/z4a;->OooO0OO()Z

    move-result p2

    if-eqz p2, :cond_e

    invoke-static {p3}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {p3}, Llyiahf/vczjk/l5a;->OooOO0(Llyiahf/vczjk/t4a;)Llyiahf/vczjk/f19;

    move-result-object p1

    return-object p1

    :cond_e
    invoke-virtual {v3}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object p2

    invoke-virtual {p2}, Llyiahf/vczjk/uk4;->o00000O()Llyiahf/vczjk/iaa;

    move-result-object p2

    invoke-virtual {v3}, Llyiahf/vczjk/z4a;->OooO00o()Llyiahf/vczjk/cda;

    move-result-object p4

    const-string v2, "getProjectionKind(...)"

    invoke-static {p4, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Llyiahf/vczjk/z4a;->OooO00o()Llyiahf/vczjk/cda;

    move-result-object p1

    invoke-static {p1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "typeAlias"

    if-ne p1, p4, :cond_f

    goto :goto_6

    :cond_f
    sget-object v3, Llyiahf/vczjk/cda;->OooOOO0:Llyiahf/vczjk/cda;

    if-ne p1, v3, :cond_10

    goto :goto_6

    :cond_10
    if-ne p4, v3, :cond_11

    move-object p4, p1

    goto :goto_6

    :cond_11
    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    :goto_6
    if-eqz p3, :cond_12

    invoke-interface {p3}, Llyiahf/vczjk/t4a;->Oooo0OO()Llyiahf/vczjk/cda;

    move-result-object p1

    if-nez p1, :cond_13

    :cond_12
    sget-object p1, Llyiahf/vczjk/cda;->OooOOO0:Llyiahf/vczjk/cda;

    :cond_13
    if-ne p1, p4, :cond_14

    goto :goto_7

    :cond_14
    sget-object p3, Llyiahf/vczjk/cda;->OooOOO0:Llyiahf/vczjk/cda;

    if-ne p1, p3, :cond_15

    goto :goto_7

    :cond_15
    if-ne p4, p3, :cond_16

    move-object p4, p3

    goto :goto_7

    :cond_16
    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    :goto_7
    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object p1

    invoke-virtual {p2}, Llyiahf/vczjk/uk4;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object p3

    invoke-virtual {p0, p1, p3}, Llyiahf/vczjk/tp3;->OooO0O0(Llyiahf/vczjk/ko;Llyiahf/vczjk/ko;)V

    invoke-static {p2}, Llyiahf/vczjk/vt6;->OooOOOO(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/dp8;

    move-result-object p1

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o000000o()Z

    move-result p2

    invoke-static {p1, p2}, Llyiahf/vczjk/l5a;->OooO(Llyiahf/vczjk/dp8;Z)Llyiahf/vczjk/dp8;

    move-result-object p1

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o0OOO0o()Llyiahf/vczjk/d3a;

    move-result-object p2

    invoke-static {p1}, Llyiahf/vczjk/jp8;->OooOooO(Llyiahf/vczjk/uk4;)Z

    move-result p3

    if-eqz p3, :cond_17

    goto/16 :goto_c

    :cond_17
    invoke-static {p1}, Llyiahf/vczjk/jp8;->OooOooO(Llyiahf/vczjk/uk4;)Z

    move-result p3

    if-eqz p3, :cond_18

    invoke-virtual {p1}, Llyiahf/vczjk/uk4;->o0OOO0o()Llyiahf/vczjk/d3a;

    move-result-object p2

    goto/16 :goto_b

    :cond_18
    invoke-virtual {p1}, Llyiahf/vczjk/uk4;->o0OOO0o()Llyiahf/vczjk/d3a;

    move-result-object p3

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v0, "other"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p2}, Llyiahf/vczjk/k10;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_19

    invoke-virtual {p3}, Llyiahf/vczjk/k10;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_19

    goto/16 :goto_b

    :cond_19
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    sget-object v1, Llyiahf/vczjk/d3a;->OooOOO:Llyiahf/vczjk/xo8;

    iget-object v1, v1, Llyiahf/vczjk/xo8;->OooOOO0:Ljava/lang/Object;

    check-cast v1, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {v1}, Ljava/util/concurrent/ConcurrentHashMap;->values()Ljava/util/Collection;

    move-result-object v1

    const-string v2, "<get-values>(...)"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_8
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1e

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    iget-object v3, p2, Llyiahf/vczjk/k10;->OooOOO0:Llyiahf/vczjk/gy;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/gy;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/qo;

    iget-object v4, p3, Llyiahf/vczjk/k10;->OooOOO0:Llyiahf/vczjk/gy;

    invoke-virtual {v4, v2}, Llyiahf/vczjk/gy;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/qo;

    if-nez v3, :cond_1c

    if-eqz v2, :cond_1b

    if-nez v3, :cond_1a

    goto :goto_a

    :cond_1a
    new-instance v4, Llyiahf/vczjk/qo;

    iget-object v2, v2, Llyiahf/vczjk/qo;->OooO00o:Llyiahf/vczjk/ko;

    iget-object v3, v3, Llyiahf/vczjk/qo;->OooO00o:Llyiahf/vczjk/ko;

    invoke-static {v2, v3}, Llyiahf/vczjk/yi4;->Oooo0OO(Llyiahf/vczjk/ko;Llyiahf/vczjk/ko;)Llyiahf/vczjk/ko;

    move-result-object v2

    invoke-direct {v4, v2}, Llyiahf/vczjk/qo;-><init>(Llyiahf/vczjk/ko;)V

    move-object v2, v4

    goto :goto_a

    :cond_1b
    move-object v2, v5

    goto :goto_a

    :cond_1c
    if-nez v2, :cond_1d

    goto :goto_9

    :cond_1d
    new-instance v4, Llyiahf/vczjk/qo;

    iget-object v3, v3, Llyiahf/vczjk/qo;->OooO00o:Llyiahf/vczjk/ko;

    iget-object v2, v2, Llyiahf/vczjk/qo;->OooO00o:Llyiahf/vczjk/ko;

    invoke-static {v3, v2}, Llyiahf/vczjk/yi4;->Oooo0OO(Llyiahf/vczjk/ko;Llyiahf/vczjk/ko;)Llyiahf/vczjk/ko;

    move-result-object v2

    invoke-direct {v4, v2}, Llyiahf/vczjk/qo;-><init>(Llyiahf/vczjk/ko;)V

    move-object v3, v4

    :goto_9
    move-object v2, v3

    :goto_a
    invoke-static {v0, v2}, Llyiahf/vczjk/t51;->OooOO0o(Ljava/util/AbstractCollection;Ljava/lang/Object;)V

    goto :goto_8

    :cond_1e
    invoke-static {v0}, Llyiahf/vczjk/xo8;->OooO0o(Ljava/util/List;)Llyiahf/vczjk/d3a;

    move-result-object p2

    :goto_b
    const/4 p3, 0x1

    invoke-static {p1, v5, p2, p3}, Llyiahf/vczjk/vt6;->OooOooo(Llyiahf/vczjk/dp8;Ljava/util/List;Llyiahf/vczjk/d3a;I)Llyiahf/vczjk/dp8;

    move-result-object p1

    :goto_c
    new-instance p2, Llyiahf/vczjk/f19;

    invoke-direct {p2, p1, p4}, Llyiahf/vczjk/f19;-><init>(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)V

    return-object p2

    :cond_1f
    move-object v6, p0

    new-instance p1, Ljava/lang/AssertionError;

    new-instance p2, Ljava/lang/StringBuilder;

    const-string p3, "Too deep recursion while expanding type alias "

    invoke-direct {p2, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    check-cast v1, Llyiahf/vczjk/w02;

    invoke-virtual {v1}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object p3

    invoke-virtual {p2, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    throw p1
.end method

.method public OooOOo0(Llyiahf/vczjk/dp8;Llyiahf/vczjk/pb7;I)Llyiahf/vczjk/dp8;
    .locals 8

    invoke-virtual {p1}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v0

    invoke-virtual {p1}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object v1

    new-instance v2, Ljava/util/ArrayList;

    const/16 v3, 0xa

    invoke-static {v1, v3}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v3

    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    const/4 v3, 0x0

    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    const/4 v5, 0x0

    if-eqz v4, :cond_2

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    add-int/lit8 v6, v3, 0x1

    if-ltz v3, :cond_1

    check-cast v4, Llyiahf/vczjk/z4a;

    invoke-interface {v0}, Llyiahf/vczjk/n3a;->OooO0OO()Ljava/util/List;

    move-result-object v5

    invoke-interface {v5, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/t4a;

    add-int/lit8 v5, p3, 0x1

    invoke-virtual {p0, v4, p2, v3, v5}, Llyiahf/vczjk/tp3;->OooOOOo(Llyiahf/vczjk/z4a;Llyiahf/vczjk/pb7;Llyiahf/vczjk/t4a;I)Llyiahf/vczjk/z4a;

    move-result-object v3

    invoke-virtual {v3}, Llyiahf/vczjk/z4a;->OooO0OO()Z

    move-result v5

    if-eqz v5, :cond_0

    goto :goto_1

    :cond_0
    new-instance v5, Llyiahf/vczjk/f19;

    invoke-virtual {v3}, Llyiahf/vczjk/z4a;->OooO00o()Llyiahf/vczjk/cda;

    move-result-object v7

    invoke-virtual {v3}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object v3

    invoke-virtual {v4}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object v4

    invoke-virtual {v4}, Llyiahf/vczjk/uk4;->o000000o()Z

    move-result v4

    invoke-static {v3, v4}, Llyiahf/vczjk/l5a;->OooO0oo(Llyiahf/vczjk/uk4;Z)Llyiahf/vczjk/uk4;

    move-result-object v3

    invoke-direct {v5, v3, v7}, Llyiahf/vczjk/f19;-><init>(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)V

    move-object v3, v5

    :goto_1
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move v3, v6

    goto :goto_0

    :cond_1
    invoke-static {}, Llyiahf/vczjk/e21;->OoooOO0()V

    throw v5

    :cond_2
    const/4 p2, 0x2

    invoke-static {p1, v2, v5, p2}, Llyiahf/vczjk/vt6;->OooOooo(Llyiahf/vczjk/dp8;Ljava/util/List;Llyiahf/vczjk/d3a;I)Llyiahf/vczjk/dp8;

    move-result-object p1

    return-object p1
.end method

.method public OooOOoo(Landroid/app/Application;Llyiahf/vczjk/wu;)Ljava/lang/String;
    .locals 1

    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v0, 0x1a

    if-lt p1, v0, :cond_0

    iget-wide p1, p2, Llyiahf/vczjk/wu;->OooOo00:J

    invoke-static {p1, p2}, Llyiahf/vczjk/cr;->OooO(J)Ljava/time/Duration;

    move-result-object p1

    invoke-static {p1}, Lgithub/tornaco/android/thanos/core/util/DateUtils;->formatDuration(Ljava/time/Duration;)Ljava/lang/String;

    move-result-object p1

    return-object p1

    :cond_0
    iget-wide p1, p2, Llyiahf/vczjk/wu;->OooOo00:J

    invoke-static {p1, p2}, Lgithub/tornaco/android/thanos/core/util/DateUtils;->formatLongForMessageTime(J)Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

.method public OoooO0(Llyiahf/vczjk/sg5;)Z
    .locals 0

    const/4 p1, 0x0

    return p1
.end method

.method public Oooooo0(Landroid/content/Context;)Ljava/util/Comparator;
    .locals 1

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p1, Llyiahf/vczjk/h93;

    const/16 v0, 0x17

    invoke-direct {p1, v0}, Llyiahf/vczjk/h93;-><init>(I)V

    return-object p1
.end method

.method public log(Ljava/lang/String;)V
    .locals 0

    invoke-static {p1}, Llyiahf/vczjk/l87;->OooO0O0(Ljava/lang/String;)V

    return-void
.end method

.method public o00Oo0(Landroid/content/Context;Llyiahf/vczjk/xw;)Ljava/lang/String;
    .locals 3

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "model"

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v0, 0x1a

    iget-wide v1, p2, Llyiahf/vczjk/xw;->OooO0o0:J

    if-lt p1, v0, :cond_0

    invoke-static {v1, v2}, Llyiahf/vczjk/cr;->OooO(J)Ljava/time/Duration;

    move-result-object p1

    invoke-static {p1}, Lgithub/tornaco/android/thanos/core/util/DateUtils;->formatDuration(Ljava/time/Duration;)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    return-object p1

    :cond_0
    invoke-static {v1, v2}, Lgithub/tornaco/android/thanos/core/util/DateUtils;->formatLongForMessageTime(J)Ljava/lang/String;

    move-result-object p1

    const-string p2, "formatLongForMessageTime(...)"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1
.end method

.method public toString()Ljava/lang/String;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/tp3;->OooOOO0:I

    sparse-switch v0, :sswitch_data_0

    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0

    :sswitch_0
    const-string v0, "NULL_VALUE"

    return-object v0

    :sswitch_1
    const-string v0, "Empty"

    return-object v0

    :sswitch_data_0
    .sparse-switch
        0xd -> :sswitch_1
        0x1b -> :sswitch_0
    .end sparse-switch
.end method
