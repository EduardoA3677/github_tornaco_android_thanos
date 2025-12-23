.class public final Llyiahf/vczjk/vu2;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/x64;

.field public final OooO0O0:[Llyiahf/vczjk/uu2;

.field public final OooO0OO:Ljava/util/HashMap;

.field public final OooO0Oo:[Ljava/lang/String;

.field public final OooO0o0:[Llyiahf/vczjk/tt9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/vu2;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iget-object v0, p1, Llyiahf/vczjk/vu2;->OooO00o:Llyiahf/vczjk/x64;

    iput-object v0, p0, Llyiahf/vczjk/vu2;->OooO00o:Llyiahf/vczjk/x64;

    iget-object v0, p1, Llyiahf/vczjk/vu2;->OooO0O0:[Llyiahf/vczjk/uu2;

    iput-object v0, p0, Llyiahf/vczjk/vu2;->OooO0O0:[Llyiahf/vczjk/uu2;

    iget-object p1, p1, Llyiahf/vczjk/vu2;->OooO0OO:Ljava/util/HashMap;

    iput-object p1, p0, Llyiahf/vczjk/vu2;->OooO0OO:Ljava/util/HashMap;

    array-length p1, v0

    new-array v0, p1, [Ljava/lang/String;

    iput-object v0, p0, Llyiahf/vczjk/vu2;->OooO0Oo:[Ljava/lang/String;

    new-array p1, p1, [Llyiahf/vczjk/tt9;

    iput-object p1, p0, Llyiahf/vczjk/vu2;->OooO0o0:[Llyiahf/vczjk/tt9;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/x64;[Llyiahf/vczjk/uu2;Ljava/util/HashMap;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/vu2;->OooO00o:Llyiahf/vczjk/x64;

    iput-object p2, p0, Llyiahf/vczjk/vu2;->OooO0O0:[Llyiahf/vczjk/uu2;

    iput-object p3, p0, Llyiahf/vczjk/vu2;->OooO0OO:Ljava/util/HashMap;

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/vu2;->OooO0Oo:[Ljava/lang/String;

    iput-object p1, p0, Llyiahf/vczjk/vu2;->OooO0o0:[Llyiahf/vczjk/tt9;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;ILjava/lang/String;)V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/vu2;->OooO0o0:[Llyiahf/vczjk/tt9;

    aget-object v0, v0, p4

    invoke-virtual {v0, p1}, Llyiahf/vczjk/tt9;->o000O0O0(Llyiahf/vczjk/eb4;)Llyiahf/vczjk/rt9;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/rt9;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    iget-object v3, p0, Llyiahf/vczjk/vu2;->OooO0O0:[Llyiahf/vczjk/uu2;

    if-ne v1, v2, :cond_0

    aget-object p1, v3, p4

    iget-object p1, p1, Llyiahf/vczjk/uu2;->OooO00o:Llyiahf/vczjk/ph8;

    const/4 p2, 0x0

    invoke-virtual {p1, p3, p2}, Llyiahf/vczjk/ph8;->OooOoO0(Ljava/lang/Object;Ljava/lang/Object;)V

    return-void

    :cond_0
    new-instance v1, Llyiahf/vczjk/tt9;

    invoke-direct {v1, p2, p1}, Llyiahf/vczjk/tt9;-><init>(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)V

    invoke-virtual {v1}, Llyiahf/vczjk/tt9;->o0000o0()V

    invoke-virtual {v1, p5}, Llyiahf/vczjk/tt9;->o0000ooO(Ljava/lang/String;)V

    invoke-virtual {v1, v0}, Llyiahf/vczjk/tt9;->o000O0oO(Llyiahf/vczjk/eb4;)V

    invoke-virtual {v1}, Llyiahf/vczjk/tt9;->o00000O()V

    invoke-virtual {v1, p1}, Llyiahf/vczjk/tt9;->o000O0O0(Llyiahf/vczjk/eb4;)Llyiahf/vczjk/rt9;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/rt9;->o0000oOO()Llyiahf/vczjk/gc4;

    aget-object p4, v3, p4

    iget-object p4, p4, Llyiahf/vczjk/uu2;->OooO00o:Llyiahf/vczjk/ph8;

    invoke-virtual {p4, p1, p2, p3}, Llyiahf/vczjk/ph8;->OooO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)V

    return-void
.end method

.method public final OooO0O0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/String;Ljava/lang/Object;Ljava/lang/String;I)Z
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/vu2;->OooO0O0:[Llyiahf/vczjk/uu2;

    aget-object v0, v0, p6

    iget-object v0, v0, Llyiahf/vczjk/uu2;->OooO0OO:Ljava/lang/String;

    invoke-virtual {p3, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p3

    if-nez p3, :cond_0

    const/4 p1, 0x0

    return p1

    :cond_0
    if-eqz p4, :cond_1

    iget-object p3, p0, Llyiahf/vczjk/vu2;->OooO0o0:[Llyiahf/vczjk/tt9;

    aget-object v0, p3, p6

    if-eqz v0, :cond_1

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p4

    move-object v6, p5

    move v5, p6

    invoke-virtual/range {v1 .. v6}, Llyiahf/vczjk/vu2;->OooO00o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;ILjava/lang/String;)V

    const/4 p1, 0x0

    aput-object p1, p3, v5

    goto :goto_0

    :cond_1
    move-object v1, p0

    move-object v6, p5

    move v5, p6

    iget-object p1, v1, Llyiahf/vczjk/vu2;->OooO0Oo:[Ljava/lang/String;

    aput-object v6, p1, v5

    :goto_0
    const/4 p1, 0x1

    return p1
.end method

.method public final OooO0OO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/lb7;Llyiahf/vczjk/oa7;)Ljava/lang/Object;
    .locals 16

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move-object/from16 v2, p2

    move-object/from16 v3, p3

    iget-object v4, v0, Llyiahf/vczjk/vu2;->OooO0O0:[Llyiahf/vczjk/uu2;

    array-length v5, v4

    new-array v6, v5, [Ljava/lang/Object;

    const/4 v7, 0x0

    move v8, v7

    :goto_0
    if-ge v8, v5, :cond_a

    iget-object v9, v0, Llyiahf/vczjk/vu2;->OooO0Oo:[Ljava/lang/String;

    aget-object v9, v9, v8

    aget-object v10, v4, v8

    const/4 v11, 0x0

    iget-object v12, v0, Llyiahf/vczjk/vu2;->OooO00o:Llyiahf/vczjk/x64;

    iget-object v13, v0, Llyiahf/vczjk/vu2;->OooO0o0:[Llyiahf/vczjk/tt9;

    if-nez v9, :cond_3

    aget-object v9, v13, v8

    if-nez v9, :cond_0

    goto/16 :goto_4

    :cond_0
    iget-object v9, v10, Llyiahf/vczjk/uu2;->OooO0O0:Llyiahf/vczjk/u3a;

    invoke-virtual {v9}, Llyiahf/vczjk/u3a;->OooO0oO()Ljava/lang/Class;

    move-result-object v9

    if-eqz v9, :cond_2

    iget-object v9, v10, Llyiahf/vczjk/uu2;->OooO0O0:Llyiahf/vczjk/u3a;

    invoke-virtual {v9}, Llyiahf/vczjk/u3a;->OooO0oO()Ljava/lang/Class;

    move-result-object v12

    if-nez v12, :cond_1

    move-object v9, v11

    goto :goto_1

    :cond_1
    invoke-virtual {v9}, Llyiahf/vczjk/u3a;->OooO()Llyiahf/vczjk/d4a;

    move-result-object v9

    invoke-interface {v9, v12, v11}, Llyiahf/vczjk/d4a;->OooO0Oo(Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v9

    goto :goto_1

    :cond_2
    iget-object v1, v10, Llyiahf/vczjk/uu2;->OooO00o:Llyiahf/vczjk/ph8;

    invoke-virtual {v1}, Llyiahf/vczjk/ph8;->getName()Ljava/lang/String;

    move-result-object v1

    iget-object v3, v10, Llyiahf/vczjk/uu2;->OooO0OO:Ljava/lang/String;

    filled-new-array {v3}, [Ljava/lang/Object;

    move-result-object v3

    const-string v4, "Missing external type id property \'%s\'"

    invoke-virtual {v2, v12, v1, v4, v3}, Llyiahf/vczjk/v72;->o0000OO(Llyiahf/vczjk/x64;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v11

    :cond_3
    aget-object v14, v13, v8

    if-nez v14, :cond_5

    iget-object v14, v10, Llyiahf/vczjk/uu2;->OooO00o:Llyiahf/vczjk/ph8;

    invoke-virtual {v14}, Llyiahf/vczjk/lh1;->OooO0o0()Z

    move-result v15

    if-nez v15, :cond_4

    sget-object v15, Llyiahf/vczjk/w72;->OooOoO:Llyiahf/vczjk/w72;

    invoke-virtual {v2, v15}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result v15

    if-nez v15, :cond_4

    goto :goto_1

    :cond_4
    invoke-virtual {v14}, Llyiahf/vczjk/ph8;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v14}, Llyiahf/vczjk/ph8;->getName()Ljava/lang/String;

    move-result-object v3

    aget-object v4, v4, v8

    iget-object v4, v4, Llyiahf/vczjk/uu2;->OooO0OO:Ljava/lang/String;

    filled-new-array {v3, v4}, [Ljava/lang/Object;

    move-result-object v3

    const-string v4, "Missing property \'%s\' for external type id \'%s\'"

    invoke-virtual {v2, v12, v1, v4, v3}, Llyiahf/vczjk/v72;->o0000OO(Llyiahf/vczjk/x64;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v11

    :cond_5
    :goto_1
    aget-object v12, v13, v8

    if-eqz v12, :cond_7

    invoke-virtual {v12, v1}, Llyiahf/vczjk/tt9;->o000O0O0(Llyiahf/vczjk/eb4;)Llyiahf/vczjk/rt9;

    move-result-object v12

    invoke-virtual {v12}, Llyiahf/vczjk/rt9;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v13

    sget-object v14, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    if-ne v13, v14, :cond_6

    goto :goto_2

    :cond_6
    new-instance v11, Llyiahf/vczjk/tt9;

    invoke-direct {v11, v2, v1}, Llyiahf/vczjk/tt9;-><init>(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)V

    invoke-virtual {v11}, Llyiahf/vczjk/tt9;->o0000o0()V

    invoke-virtual {v11, v9}, Llyiahf/vczjk/tt9;->o0000ooO(Ljava/lang/String;)V

    invoke-virtual {v11, v12}, Llyiahf/vczjk/tt9;->o000O0oO(Llyiahf/vczjk/eb4;)V

    invoke-virtual {v11}, Llyiahf/vczjk/tt9;->o00000O()V

    invoke-virtual {v11, v1}, Llyiahf/vczjk/tt9;->o000O0O0(Llyiahf/vczjk/eb4;)Llyiahf/vczjk/rt9;

    move-result-object v11

    invoke-virtual {v11}, Llyiahf/vczjk/rt9;->o0000oOO()Llyiahf/vczjk/gc4;

    aget-object v12, v4, v8

    iget-object v12, v12, Llyiahf/vczjk/uu2;->OooO00o:Llyiahf/vczjk/ph8;

    invoke-virtual {v12, v2, v11}, Llyiahf/vczjk/ph8;->OooO0oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v11

    :goto_2
    aput-object v11, v6, v8

    :cond_7
    iget-object v11, v10, Llyiahf/vczjk/uu2;->OooO00o:Llyiahf/vczjk/ph8;

    invoke-virtual {v11}, Llyiahf/vczjk/ph8;->OooOOO0()I

    move-result v12

    if-ltz v12, :cond_9

    aget-object v12, v6, v8

    invoke-virtual {v3, v11, v12}, Llyiahf/vczjk/lb7;->OooO0O0(Llyiahf/vczjk/ph8;Ljava/lang/Object;)Z

    iget-object v10, v10, Llyiahf/vczjk/uu2;->OooO0Oo:Llyiahf/vczjk/ph8;

    if-eqz v10, :cond_9

    invoke-virtual {v10}, Llyiahf/vczjk/ph8;->OooOOO0()I

    move-result v11

    if-ltz v11, :cond_9

    invoke-virtual {v10}, Llyiahf/vczjk/ph8;->getType()Llyiahf/vczjk/x64;

    move-result-object v11

    const-class v12, Ljava/lang/String;

    invoke-virtual {v11, v12}, Llyiahf/vczjk/x64;->Ooooo00(Ljava/lang/Class;)Z

    move-result v11

    if-eqz v11, :cond_8

    goto :goto_3

    :cond_8
    new-instance v11, Llyiahf/vczjk/tt9;

    invoke-direct {v11, v2, v1}, Llyiahf/vczjk/tt9;-><init>(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)V

    invoke-virtual {v11, v9}, Llyiahf/vczjk/tt9;->o0000ooO(Ljava/lang/String;)V

    invoke-virtual {v10}, Llyiahf/vczjk/ph8;->OooOOo0()Llyiahf/vczjk/e94;

    move-result-object v9

    iget-object v12, v11, Llyiahf/vczjk/tt9;->OooOOO:Llyiahf/vczjk/l66;

    invoke-virtual {v11, v12}, Llyiahf/vczjk/tt9;->o000O0o0(Llyiahf/vczjk/l66;)Llyiahf/vczjk/rt9;

    move-result-object v11

    invoke-virtual {v11}, Llyiahf/vczjk/rt9;->o0000oOO()Llyiahf/vczjk/gc4;

    invoke-virtual {v9, v2, v11}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v9

    :goto_3
    invoke-virtual {v3, v10, v9}, Llyiahf/vczjk/lb7;->OooO0O0(Llyiahf/vczjk/ph8;Ljava/lang/Object;)Z

    :cond_9
    :goto_4
    add-int/lit8 v8, v8, 0x1

    goto/16 :goto_0

    :cond_a
    move-object/from16 v8, p4

    invoke-virtual {v8, v2, v3}, Llyiahf/vczjk/oa7;->OooO00o(Llyiahf/vczjk/v72;Llyiahf/vczjk/lb7;)Ljava/lang/Object;

    move-result-object v1

    :goto_5
    if-ge v7, v5, :cond_c

    aget-object v2, v4, v7

    iget-object v2, v2, Llyiahf/vczjk/uu2;->OooO00o:Llyiahf/vczjk/ph8;

    invoke-virtual {v2}, Llyiahf/vczjk/ph8;->OooOOO0()I

    move-result v3

    if-gez v3, :cond_b

    aget-object v3, v6, v7

    invoke-virtual {v2, v1, v3}, Llyiahf/vczjk/ph8;->OooOoO0(Ljava/lang/Object;Ljava/lang/Object;)V

    :cond_b
    add-int/lit8 v7, v7, 0x1

    goto :goto_5

    :cond_c
    return-object v1
.end method

.method public final OooO0Oo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)V
    .locals 9

    iget-object v0, p0, Llyiahf/vczjk/vu2;->OooO0O0:[Llyiahf/vczjk/uu2;

    array-length v1, v0

    const/4 v2, 0x0

    move v7, v2

    :goto_0
    if-ge v7, v1, :cond_9

    iget-object v3, p0, Llyiahf/vczjk/vu2;->OooO0Oo:[Ljava/lang/String;

    aget-object v3, v3, v7

    iget-object v4, p0, Llyiahf/vczjk/vu2;->OooO0o0:[Llyiahf/vczjk/tt9;

    if-nez v3, :cond_6

    aget-object v4, v4, v7

    if-nez v4, :cond_0

    :goto_1
    move-object v4, p1

    move-object v5, p2

    move-object v6, p3

    goto/16 :goto_4

    :cond_0
    iget-object v5, v4, Llyiahf/vczjk/tt9;->OooOo0:Llyiahf/vczjk/st9;

    invoke-virtual {v5, v2}, Llyiahf/vczjk/st9;->OooO0OO(I)Llyiahf/vczjk/gc4;

    move-result-object v5

    invoke-virtual {v5}, Llyiahf/vczjk/gc4;->OooO0o0()Z

    move-result v5

    if-eqz v5, :cond_5

    invoke-virtual {v4, p1}, Llyiahf/vczjk/tt9;->o000O0O0(Llyiahf/vczjk/eb4;)Llyiahf/vczjk/rt9;

    move-result-object v3

    invoke-virtual {v3}, Llyiahf/vczjk/rt9;->o0000oOO()Llyiahf/vczjk/gc4;

    aget-object v4, v0, v7

    iget-object v4, v4, Llyiahf/vczjk/uu2;->OooO00o:Llyiahf/vczjk/ph8;

    invoke-virtual {v4}, Llyiahf/vczjk/ph8;->getType()Llyiahf/vczjk/x64;

    move-result-object v5

    invoke-static {v5, v3}, Llyiahf/vczjk/u3a;->OooO00o(Llyiahf/vczjk/x64;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v3

    if-eqz v3, :cond_1

    invoke-virtual {v4, p3, v3}, Llyiahf/vczjk/ph8;->OooOoO0(Ljava/lang/Object;Ljava/lang/Object;)V

    goto :goto_1

    :cond_1
    aget-object v3, v0, v7

    iget-object v3, v3, Llyiahf/vczjk/uu2;->OooO0O0:Llyiahf/vczjk/u3a;

    invoke-virtual {v3}, Llyiahf/vczjk/u3a;->OooO0oO()Ljava/lang/Class;

    move-result-object v3

    if-eqz v3, :cond_3

    aget-object v3, v0, v7

    iget-object v3, v3, Llyiahf/vczjk/uu2;->OooO0O0:Llyiahf/vczjk/u3a;

    invoke-virtual {v3}, Llyiahf/vczjk/u3a;->OooO0oO()Ljava/lang/Class;

    move-result-object v4

    const/4 v5, 0x0

    if-nez v4, :cond_2

    move-object v3, v5

    goto :goto_2

    :cond_2
    invoke-virtual {v3}, Llyiahf/vczjk/u3a;->OooO()Llyiahf/vczjk/d4a;

    move-result-object v3

    invoke-interface {v3, v4, v5}, Llyiahf/vczjk/d4a;->OooO0Oo(Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v3

    goto :goto_2

    :cond_3
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p1

    invoke-virtual {v4}, Llyiahf/vczjk/ph8;->getName()Ljava/lang/String;

    move-result-object p3

    aget-object v0, v0, v7

    iget-object v0, v0, Llyiahf/vczjk/uu2;->OooO0OO:Ljava/lang/String;

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v1, "Missing external type id property \'%s\'"

    invoke-static {v1, v0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/qj5;

    iget-object p2, p2, Llyiahf/vczjk/v72;->OooOo:Llyiahf/vczjk/eb4;

    invoke-direct {v1, p2, v0, p1}, Llyiahf/vczjk/qj5;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Ljava/lang/Class;)V

    if-eqz p3, :cond_4

    new-instance p2, Llyiahf/vczjk/ma4;

    invoke-direct {p2, p1, p3}, Llyiahf/vczjk/ma4;-><init>(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1, p2}, Llyiahf/vczjk/na4;->OooO0o(Llyiahf/vczjk/ma4;)V

    :cond_4
    throw v1

    :cond_5
    :goto_2
    move-object v4, p1

    move-object v5, p2

    move-object v6, p3

    move-object v8, v3

    move-object v3, p0

    goto :goto_3

    :cond_6
    aget-object v4, v4, v7

    if-nez v4, :cond_5

    aget-object p1, v0, v7

    iget-object p1, p1, Llyiahf/vczjk/uu2;->OooO00o:Llyiahf/vczjk/ph8;

    invoke-virtual {p1}, Llyiahf/vczjk/lh1;->OooO0o0()Z

    move-result v1

    if-nez v1, :cond_7

    sget-object v1, Llyiahf/vczjk/w72;->OooOoO:Llyiahf/vczjk/w72;

    invoke-virtual {p2, v1}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result v1

    if-nez v1, :cond_7

    goto :goto_5

    :cond_7
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p3

    invoke-virtual {p1}, Llyiahf/vczjk/ph8;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1}, Llyiahf/vczjk/ph8;->getName()Ljava/lang/String;

    move-result-object p1

    aget-object v0, v0, v7

    iget-object v0, v0, Llyiahf/vczjk/uu2;->OooO0OO:Ljava/lang/String;

    filled-new-array {p1, v0}, [Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v0, "Missing property \'%s\' for external type id \'%s\'"

    invoke-static {v0, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/qj5;

    iget-object p2, p2, Llyiahf/vczjk/v72;->OooOo:Llyiahf/vczjk/eb4;

    invoke-direct {v0, p2, p1, p3}, Llyiahf/vczjk/qj5;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Ljava/lang/Class;)V

    if-eqz v1, :cond_8

    new-instance p1, Llyiahf/vczjk/ma4;

    invoke-direct {p1, p3, v1}, Llyiahf/vczjk/ma4;-><init>(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Llyiahf/vczjk/na4;->OooO0o(Llyiahf/vczjk/ma4;)V

    :cond_8
    throw v0

    :goto_3
    invoke-virtual/range {v3 .. v8}, Llyiahf/vczjk/vu2;->OooO00o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;ILjava/lang/String;)V

    :goto_4
    add-int/lit8 v7, v7, 0x1

    move-object p1, v4

    move-object p2, v5

    move-object p3, v6

    goto/16 :goto_0

    :cond_9
    :goto_5
    return-void
.end method

.method public final OooO0o(Ljava/lang/Object;Ljava/lang/String;Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)V
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/vu2;->OooO0OO:Ljava/util/HashMap;

    invoke-virtual {v0, p2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    if-nez v0, :cond_0

    goto :goto_1

    :cond_0
    invoke-virtual {p4}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object v6

    instance-of v1, v0, Ljava/util/List;

    if-eqz v1, :cond_2

    check-cast v0, Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Integer;

    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    move-result v7

    move-object v1, p0

    move-object v5, p1

    move-object v4, p2

    move-object v3, p3

    move-object v2, p4

    invoke-virtual/range {v1 .. v7}, Llyiahf/vczjk/vu2;->OooO0O0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/String;Ljava/lang/Object;Ljava/lang/String;I)Z

    move-object p4, v2

    move-object p3, v3

    move-object p2, v4

    move-object p1, v5

    goto :goto_0

    :cond_1
    :goto_1
    return-void

    :cond_2
    move-object v5, p1

    move-object v4, p2

    move-object v3, p3

    move-object v2, p4

    check-cast v0, Ljava/lang/Integer;

    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    move-result v7

    move-object v1, p0

    invoke-virtual/range {v1 .. v7}, Llyiahf/vczjk/vu2;->OooO0O0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/String;Ljava/lang/Object;Ljava/lang/String;I)Z

    return-void
.end method

.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/String;Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Z
    .locals 11

    iget-object v4, p0, Llyiahf/vczjk/vu2;->OooO0OO:Ljava/util/HashMap;

    invoke-virtual {v4, p2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    if-nez v4, :cond_0

    const/4 v1, 0x0

    return v1

    :cond_0
    instance-of v5, v4, Ljava/util/List;

    const/4 v6, 0x1

    iget-object v7, p0, Llyiahf/vczjk/vu2;->OooO0O0:[Llyiahf/vczjk/uu2;

    iget-object v8, p0, Llyiahf/vczjk/vu2;->OooO0o0:[Llyiahf/vczjk/tt9;

    iget-object v9, p0, Llyiahf/vczjk/vu2;->OooO0Oo:[Ljava/lang/String;

    if-eqz v5, :cond_2

    check-cast v4, Ljava/util/List;

    invoke-interface {v4}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v4

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/lang/Integer;

    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    move-result v10

    aget-object v7, v7, v10

    iget-object v7, v7, Llyiahf/vczjk/uu2;->OooO0OO:Ljava/lang/String;

    invoke-virtual {p2, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-virtual {p4}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p4}, Llyiahf/vczjk/eb4;->o000Ooo()Llyiahf/vczjk/eb4;

    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    move-result v2

    aput-object v1, v9, v2

    :goto_0
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_4

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Integer;

    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    move-result v2

    aput-object v1, v9, v2

    goto :goto_0

    :cond_1
    new-instance v1, Llyiahf/vczjk/tt9;

    invoke-direct {v1, p3, p4}, Llyiahf/vczjk/tt9;-><init>(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)V

    invoke-virtual {v1, p4}, Llyiahf/vczjk/tt9;->o000O0oO(Llyiahf/vczjk/eb4;)V

    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    move-result v2

    aput-object v1, v8, v2

    :goto_1
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_4

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Integer;

    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    move-result v2

    aput-object v1, v8, v2

    goto :goto_1

    :cond_2
    check-cast v4, Ljava/lang/Integer;

    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    move-result v4

    aget-object v5, v7, v4

    iget-object v5, v5, Llyiahf/vczjk/uu2;->OooO0OO:Ljava/lang/String;

    invoke-virtual {p2, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_3

    invoke-virtual {p4}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object v1

    aput-object v1, v9, v4

    invoke-virtual {p4}, Llyiahf/vczjk/eb4;->o000Ooo()Llyiahf/vczjk/eb4;

    if-eqz p1, :cond_4

    aget-object v1, v8, v4

    if-eqz v1, :cond_4

    goto :goto_2

    :cond_3
    new-instance v1, Llyiahf/vczjk/tt9;

    invoke-direct {v1, p3, p4}, Llyiahf/vczjk/tt9;-><init>(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)V

    invoke-virtual {v1, p4}, Llyiahf/vczjk/tt9;->o000O0oO(Llyiahf/vczjk/eb4;)V

    aput-object v1, v8, v4

    if-eqz p1, :cond_4

    aget-object v1, v9, v4

    if-eqz v1, :cond_4

    :goto_2
    aget-object v5, v9, v4

    const/4 v7, 0x0

    aput-object v7, v9, v4

    move-object v0, p0

    move-object v3, p1

    move-object v2, p3

    move-object v1, p4

    invoke-virtual/range {v0 .. v5}, Llyiahf/vczjk/vu2;->OooO00o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;ILjava/lang/String;)V

    aput-object v7, v8, v4

    :cond_4
    return v6
.end method
