.class public final Llyiahf/vczjk/rp6;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO0oO:Ljava/util/HashMap;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/w78;

.field public OooO0O0:Llyiahf/vczjk/er2;

.field public final OooO0OO:Llyiahf/vczjk/uz5;

.field public final OooO0Oo:Llyiahf/vczjk/uz5;

.field public OooO0o:Llyiahf/vczjk/bp8;

.field public OooO0o0:Llyiahf/vczjk/t77;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    sput-object v0, Llyiahf/vczjk/rp6;->OooO0oO:Ljava/util/HashMap;

    const-string v1, "!"

    invoke-virtual {v0, v1, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const-string v1, "!!"

    const-string v2, "tag:yaml.org,2002:"

    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/b69;)V
    .locals 3

    new-instance v0, Llyiahf/vczjk/w78;

    invoke-direct {v0, p1}, Llyiahf/vczjk/w78;-><init>(Llyiahf/vczjk/b69;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/rp6;->OooO00o:Llyiahf/vczjk/w78;

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/rp6;->OooO0O0:Llyiahf/vczjk/er2;

    new-instance v0, Llyiahf/vczjk/bp8;

    new-instance v1, Ljava/util/HashMap;

    sget-object v2, Llyiahf/vczjk/rp6;->OooO0oO:Ljava/util/HashMap;

    invoke-direct {v1, v2}, Ljava/util/HashMap;-><init>(Ljava/util/Map;)V

    const/4 v2, 0x4

    invoke-direct {v0, v2, p1, v1}, Llyiahf/vczjk/bp8;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    iput-object v0, p0, Llyiahf/vczjk/rp6;->OooO0o:Llyiahf/vczjk/bp8;

    new-instance p1, Llyiahf/vczjk/uz5;

    const/16 v0, 0x64

    invoke-direct {p1, v0}, Llyiahf/vczjk/uz5;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/rp6;->OooO0OO:Llyiahf/vczjk/uz5;

    new-instance p1, Llyiahf/vczjk/uz5;

    const/16 v0, 0xa

    invoke-direct {p1, v0}, Llyiahf/vczjk/uz5;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/rp6;->OooO0Oo:Llyiahf/vczjk/uz5;

    new-instance p1, Llyiahf/vczjk/pp6;

    const/16 v0, 0x12

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/pp6;-><init>(Llyiahf/vczjk/rp6;I)V

    iput-object p1, p0, Llyiahf/vczjk/rp6;->OooO0o0:Llyiahf/vczjk/t77;

    return-void
.end method

.method public static OooO00o(Llyiahf/vczjk/rp6;Llyiahf/vczjk/mc5;)Llyiahf/vczjk/o78;
    .locals 8

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v0, Llyiahf/vczjk/o78;

    new-instance v3, Llyiahf/vczjk/c73;

    const/4 p0, 0x1

    const/4 v1, 0x0

    const/4 v2, 0x1

    invoke-direct {v3, v2, p0, v1}, Llyiahf/vczjk/c73;-><init>(IZZ)V

    sget-object v7, Llyiahf/vczjk/tj2;->OooOOo0:Llyiahf/vczjk/tj2;

    const-string v4, ""

    const/4 v1, 0x0

    const/4 v2, 0x0

    move-object v6, p1

    move-object v5, p1

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/o78;-><init>(Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/c73;Ljava/lang/String;Llyiahf/vczjk/mc5;Llyiahf/vczjk/mc5;Llyiahf/vczjk/tj2;)V

    return-object v0
.end method


# virtual methods
.method public final OooO0O0(I)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/rp6;->OooO0O0:Llyiahf/vczjk/er2;

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/rp6;->OooO0o0:Llyiahf/vczjk/t77;

    if-eqz v0, :cond_0

    invoke-interface {v0}, Llyiahf/vczjk/t77;->OooO00o()Llyiahf/vczjk/er2;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/rp6;->OooO0O0:Llyiahf/vczjk/er2;

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/rp6;->OooO0O0:Llyiahf/vczjk/er2;

    if-eqz v0, :cond_2

    invoke-virtual {v0}, Llyiahf/vczjk/er2;->OooO0O0()I

    move-result v0

    if-ne v0, p1, :cond_1

    const/4 p1, 0x1

    goto :goto_0

    :cond_1
    const/4 p1, 0x0

    :goto_0
    if-eqz p1, :cond_2

    const/4 p1, 0x1

    return p1

    :cond_2
    const/4 p1, 0x0

    return p1
.end method

.method public final OooO0OO()Llyiahf/vczjk/er2;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/rp6;->OooO0O0:Llyiahf/vczjk/er2;

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/rp6;->OooO0o0:Llyiahf/vczjk/t77;

    if-eqz v0, :cond_0

    invoke-interface {v0}, Llyiahf/vczjk/t77;->OooO00o()Llyiahf/vczjk/er2;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/rp6;->OooO0O0:Llyiahf/vczjk/er2;

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/rp6;->OooO0O0:Llyiahf/vczjk/er2;

    const/4 v1, 0x0

    iput-object v1, p0, Llyiahf/vczjk/rp6;->OooO0O0:Llyiahf/vczjk/er2;

    return-object v0
.end method

.method public final OooO0Oo(ZZ)Llyiahf/vczjk/w16;
    .locals 17

    move-object/from16 v0, p0

    sget-object v1, Llyiahf/vczjk/nt9;->OooOOO0:Llyiahf/vczjk/nt9;

    filled-new-array {v1}, [Llyiahf/vczjk/nt9;

    move-result-object v1

    iget-object v2, v0, Llyiahf/vczjk/rp6;->OooO00o:Llyiahf/vczjk/w78;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/w78;->OooO0O0([Llyiahf/vczjk/nt9;)Z

    move-result v1

    iget-object v3, v0, Llyiahf/vczjk/rp6;->OooO0OO:Llyiahf/vczjk/uz5;

    if-eqz v1, :cond_1

    invoke-virtual {v2}, Llyiahf/vczjk/w78;->OooO()Llyiahf/vczjk/qt9;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/l4;

    new-instance v2, Llyiahf/vczjk/k4;

    iget-object v4, v1, Llyiahf/vczjk/l4;->OooO0OO:Ljava/lang/String;

    iget-object v5, v1, Llyiahf/vczjk/qt9;->OooO00o:Llyiahf/vczjk/mc5;

    iget-object v1, v1, Llyiahf/vczjk/qt9;->OooO0O0:Llyiahf/vczjk/mc5;

    invoke-direct {v2, v4, v5, v1}, Llyiahf/vczjk/w16;-><init>(Ljava/lang/String;Llyiahf/vczjk/mc5;Llyiahf/vczjk/mc5;)V

    if-eqz v4, :cond_0

    invoke-virtual {v3}, Llyiahf/vczjk/uz5;->OoooOoo()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/t77;

    iput-object v1, v0, Llyiahf/vczjk/rp6;->OooO0o0:Llyiahf/vczjk/t77;

    return-object v2

    :cond_0
    new-instance v1, Ljava/lang/NullPointerException;

    const-string v2, "anchor is not specified for alias"

    invoke-direct {v1, v2}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_1
    sget-object v1, Llyiahf/vczjk/nt9;->OooOOO:Llyiahf/vczjk/nt9;

    filled-new-array {v1}, [Llyiahf/vczjk/nt9;

    move-result-object v4

    invoke-virtual {v2, v4}, Llyiahf/vczjk/w78;->OooO0O0([Llyiahf/vczjk/nt9;)Z

    move-result v4

    sget-object v5, Llyiahf/vczjk/nt9;->OooOooo:Llyiahf/vczjk/nt9;

    const/4 v6, 0x0

    if-eqz v4, :cond_3

    invoke-virtual {v2}, Llyiahf/vczjk/w78;->OooO()Llyiahf/vczjk/qt9;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/h7;

    iget-object v4, v1, Llyiahf/vczjk/qt9;->OooO00o:Llyiahf/vczjk/mc5;

    filled-new-array {v5}, [Llyiahf/vczjk/nt9;

    move-result-object v5

    invoke-virtual {v2, v5}, Llyiahf/vczjk/w78;->OooO0O0([Llyiahf/vczjk/nt9;)Z

    move-result v5

    if-eqz v5, :cond_2

    invoke-virtual {v2}, Llyiahf/vczjk/w78;->OooO()Llyiahf/vczjk/qt9;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/af9;

    iget-object v7, v5, Llyiahf/vczjk/qt9;->OooO00o:Llyiahf/vczjk/mc5;

    iget-object v8, v5, Llyiahf/vczjk/qt9;->OooO0O0:Llyiahf/vczjk/mc5;

    iget-object v5, v5, Llyiahf/vczjk/af9;->OooO0OO:Llyiahf/vczjk/ya4;

    goto :goto_0

    :cond_2
    iget-object v8, v1, Llyiahf/vczjk/qt9;->OooO0O0:Llyiahf/vczjk/mc5;

    move-object v5, v6

    move-object v7, v5

    :goto_0
    iget-object v1, v1, Llyiahf/vczjk/h7;->OooO0OO:Ljava/lang/String;

    move-object v10, v1

    move-object v13, v4

    move-object v15, v7

    goto :goto_2

    :cond_3
    filled-new-array {v5}, [Llyiahf/vczjk/nt9;

    move-result-object v4

    invoke-virtual {v2, v4}, Llyiahf/vczjk/w78;->OooO0O0([Llyiahf/vczjk/nt9;)Z

    move-result v4

    if-eqz v4, :cond_5

    invoke-virtual {v2}, Llyiahf/vczjk/w78;->OooO()Llyiahf/vczjk/qt9;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/af9;

    iget-object v5, v4, Llyiahf/vczjk/qt9;->OooO00o:Llyiahf/vczjk/mc5;

    filled-new-array {v1}, [Llyiahf/vczjk/nt9;

    move-result-object v1

    invoke-virtual {v2, v1}, Llyiahf/vczjk/w78;->OooO0O0([Llyiahf/vczjk/nt9;)Z

    move-result v1

    iget-object v7, v4, Llyiahf/vczjk/af9;->OooO0OO:Llyiahf/vczjk/ya4;

    if-eqz v1, :cond_4

    invoke-virtual {v2}, Llyiahf/vczjk/w78;->OooO()Llyiahf/vczjk/qt9;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/h7;

    iget-object v8, v1, Llyiahf/vczjk/qt9;->OooO0O0:Llyiahf/vczjk/mc5;

    iget-object v1, v1, Llyiahf/vczjk/h7;->OooO0OO:Ljava/lang/String;

    move-object v10, v1

    move-object v13, v5

    move-object v15, v13

    :goto_1
    move-object v5, v7

    goto :goto_2

    :cond_4
    iget-object v8, v4, Llyiahf/vczjk/qt9;->OooO0O0:Llyiahf/vczjk/mc5;

    move-object v13, v5

    move-object v15, v13

    move-object v10, v6

    goto :goto_1

    :cond_5
    move-object v5, v6

    move-object v8, v5

    move-object v10, v8

    move-object v13, v10

    move-object v15, v13

    :goto_2
    if-eqz v5, :cond_6

    iget-object v1, v5, Llyiahf/vczjk/ya4;->OooO0O0:Ljava/lang/String;

    iget-object v6, v5, Llyiahf/vczjk/ya4;->OooO0OO:Ljava/lang/String;

    if-eqz v1, :cond_6

    iget-object v4, v0, Llyiahf/vczjk/rp6;->OooO0o:Llyiahf/vczjk/bp8;

    iget-object v4, v4, Llyiahf/vczjk/bp8;->OooOOOO:Ljava/lang/Object;

    check-cast v4, Ljava/util/HashMap;

    invoke-virtual {v4, v1}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_7

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v5, v0, Llyiahf/vczjk/rp6;->OooO0o:Llyiahf/vczjk/bp8;

    iget-object v5, v5, Llyiahf/vczjk/bp8;->OooOOOO:Ljava/lang/Object;

    check-cast v5, Ljava/util/HashMap;

    invoke-virtual {v5, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    invoke-static {v4, v1, v6}, Llyiahf/vczjk/ix8;->OooOO0(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v6

    :cond_6
    move-object v11, v6

    goto :goto_3

    :cond_7
    new-instance v11, Llyiahf/vczjk/op6;

    const-string v2, "found undefined tag handle "

    invoke-virtual {v2, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v14

    const/16 v16, 0x0

    const-string v12, "while parsing a node"

    invoke-direct/range {v11 .. v16}, Llyiahf/vczjk/sc5;-><init>(Ljava/lang/String;Llyiahf/vczjk/mc5;Ljava/lang/String;Llyiahf/vczjk/mc5;Ljava/lang/Exception;)V

    throw v11

    :goto_3
    if-nez v13, :cond_8

    invoke-virtual {v2}, Llyiahf/vczjk/w78;->OooOO0O()Llyiahf/vczjk/qt9;

    move-result-object v1

    iget-object v13, v1, Llyiahf/vczjk/qt9;->OooO00o:Llyiahf/vczjk/mc5;

    move-object v15, v13

    goto :goto_4

    :cond_8
    move-object v15, v8

    :goto_4
    const-string v1, "!"

    const/4 v4, 0x1

    const/4 v5, 0x0

    if-eqz v11, :cond_a

    invoke-virtual {v11, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_9

    goto :goto_6

    :cond_9
    move v12, v5

    :goto_5
    move-object v8, v15

    goto :goto_7

    :cond_a
    :goto_6
    move v12, v4

    goto :goto_5

    :goto_7
    sget-object v15, Llyiahf/vczjk/sj2;->OooOOO:Llyiahf/vczjk/sj2;

    if-eqz p2, :cond_b

    sget-object v6, Llyiahf/vczjk/nt9;->OooOOOo:Llyiahf/vczjk/nt9;

    filled-new-array {v6}, [Llyiahf/vczjk/nt9;

    move-result-object v6

    invoke-virtual {v2, v6}, Llyiahf/vczjk/w78;->OooO0O0([Llyiahf/vczjk/nt9;)Z

    move-result v6

    if-eqz v6, :cond_b

    invoke-virtual {v2}, Llyiahf/vczjk/w78;->OooOO0O()Llyiahf/vczjk/qt9;

    move-result-object v1

    iget-object v14, v1, Llyiahf/vczjk/qt9;->OooO0O0:Llyiahf/vczjk/mc5;

    new-instance v9, Llyiahf/vczjk/zf8;

    invoke-direct/range {v9 .. v15}, Llyiahf/vczjk/z11;-><init>(Ljava/lang/String;Ljava/lang/String;ZLlyiahf/vczjk/mc5;Llyiahf/vczjk/mc5;Llyiahf/vczjk/sj2;)V

    new-instance v1, Llyiahf/vczjk/pp6;

    const/16 v2, 0x11

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/pp6;-><init>(Llyiahf/vczjk/rp6;I)V

    iput-object v1, v0, Llyiahf/vczjk/rp6;->OooO0o0:Llyiahf/vczjk/t77;

    return-object v9

    :cond_b
    sget-object v6, Llyiahf/vczjk/nt9;->OooOoo0:Llyiahf/vczjk/nt9;

    filled-new-array {v6}, [Llyiahf/vczjk/nt9;

    move-result-object v6

    invoke-virtual {v2, v6}, Llyiahf/vczjk/w78;->OooO0O0([Llyiahf/vczjk/nt9;)Z

    move-result v6

    if-eqz v6, :cond_10

    invoke-virtual {v2}, Llyiahf/vczjk/w78;->OooO()Llyiahf/vczjk/qt9;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/q78;

    iget-object v15, v2, Llyiahf/vczjk/qt9;->OooO0O0:Llyiahf/vczjk/mc5;

    iget-boolean v6, v2, Llyiahf/vczjk/q78;->OooO0Oo:Z

    if-eqz v6, :cond_c

    if-eqz v11, :cond_d

    :cond_c
    invoke-virtual {v1, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_e

    :cond_d
    new-instance v1, Llyiahf/vczjk/c73;

    const/4 v6, 0x1

    invoke-direct {v1, v6, v4, v5}, Llyiahf/vczjk/c73;-><init>(IZZ)V

    :goto_8
    move-object v12, v1

    goto :goto_9

    :cond_e
    if-nez v11, :cond_f

    new-instance v1, Llyiahf/vczjk/c73;

    const/4 v6, 0x1

    invoke-direct {v1, v6, v5, v4}, Llyiahf/vczjk/c73;-><init>(IZZ)V

    goto :goto_8

    :cond_f
    new-instance v1, Llyiahf/vczjk/c73;

    const/4 v4, 0x1

    invoke-direct {v1, v4, v5, v5}, Llyiahf/vczjk/c73;-><init>(IZZ)V

    goto :goto_8

    :goto_9
    new-instance v9, Llyiahf/vczjk/o78;

    move-object v14, v13

    iget-object v13, v2, Llyiahf/vczjk/q78;->OooO0OO:Ljava/lang/String;

    iget-object v1, v2, Llyiahf/vczjk/q78;->OooO0o0:Llyiahf/vczjk/tj2;

    move-object/from16 v16, v1

    invoke-direct/range {v9 .. v16}, Llyiahf/vczjk/o78;-><init>(Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/c73;Ljava/lang/String;Llyiahf/vczjk/mc5;Llyiahf/vczjk/mc5;Llyiahf/vczjk/tj2;)V

    invoke-virtual {v3}, Llyiahf/vczjk/uz5;->OoooOoo()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/t77;

    iput-object v1, v0, Llyiahf/vczjk/rp6;->OooO0o0:Llyiahf/vczjk/t77;

    return-object v9

    :cond_10
    sget-object v1, Llyiahf/vczjk/nt9;->OooOoO:Llyiahf/vczjk/nt9;

    filled-new-array {v1}, [Llyiahf/vczjk/nt9;

    move-result-object v1

    invoke-virtual {v2, v1}, Llyiahf/vczjk/w78;->OooO0O0([Llyiahf/vczjk/nt9;)Z

    move-result v1

    move-object v4, v15

    sget-object v15, Llyiahf/vczjk/sj2;->OooOOO0:Llyiahf/vczjk/sj2;

    if-eqz v1, :cond_11

    invoke-virtual {v2}, Llyiahf/vczjk/w78;->OooOO0O()Llyiahf/vczjk/qt9;

    move-result-object v1

    iget-object v14, v1, Llyiahf/vczjk/qt9;->OooO0O0:Llyiahf/vczjk/mc5;

    new-instance v9, Llyiahf/vczjk/zf8;

    invoke-direct/range {v9 .. v15}, Llyiahf/vczjk/z11;-><init>(Ljava/lang/String;Ljava/lang/String;ZLlyiahf/vczjk/mc5;Llyiahf/vczjk/mc5;Llyiahf/vczjk/sj2;)V

    new-instance v1, Llyiahf/vczjk/pp6;

    const/16 v2, 0xf

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/pp6;-><init>(Llyiahf/vczjk/rp6;I)V

    iput-object v1, v0, Llyiahf/vczjk/rp6;->OooO0o0:Llyiahf/vczjk/t77;

    return-object v9

    :cond_11
    sget-object v1, Llyiahf/vczjk/nt9;->OooOo:Llyiahf/vczjk/nt9;

    filled-new-array {v1}, [Llyiahf/vczjk/nt9;

    move-result-object v1

    invoke-virtual {v2, v1}, Llyiahf/vczjk/w78;->OooO0O0([Llyiahf/vczjk/nt9;)Z

    move-result v1

    if-eqz v1, :cond_12

    invoke-virtual {v2}, Llyiahf/vczjk/w78;->OooOO0O()Llyiahf/vczjk/qt9;

    move-result-object v1

    iget-object v14, v1, Llyiahf/vczjk/qt9;->OooO0O0:Llyiahf/vczjk/mc5;

    new-instance v9, Llyiahf/vczjk/kc5;

    invoke-direct/range {v9 .. v15}, Llyiahf/vczjk/z11;-><init>(Ljava/lang/String;Ljava/lang/String;ZLlyiahf/vczjk/mc5;Llyiahf/vczjk/mc5;Llyiahf/vczjk/sj2;)V

    new-instance v1, Llyiahf/vczjk/pp6;

    const/16 v2, 0xa

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/pp6;-><init>(Llyiahf/vczjk/rp6;I)V

    iput-object v1, v0, Llyiahf/vczjk/rp6;->OooO0o0:Llyiahf/vczjk/t77;

    return-object v9

    :cond_12
    if-eqz p1, :cond_13

    sget-object v1, Llyiahf/vczjk/nt9;->OooOOo:Llyiahf/vczjk/nt9;

    filled-new-array {v1}, [Llyiahf/vczjk/nt9;

    move-result-object v1

    invoke-virtual {v2, v1}, Llyiahf/vczjk/w78;->OooO0O0([Llyiahf/vczjk/nt9;)Z

    move-result v1

    if-eqz v1, :cond_13

    invoke-virtual {v2}, Llyiahf/vczjk/w78;->OooOO0O()Llyiahf/vczjk/qt9;

    move-result-object v1

    iget-object v14, v1, Llyiahf/vczjk/qt9;->OooO00o:Llyiahf/vczjk/mc5;

    new-instance v9, Llyiahf/vczjk/zf8;

    move-object v15, v4

    invoke-direct/range {v9 .. v15}, Llyiahf/vczjk/z11;-><init>(Ljava/lang/String;Ljava/lang/String;ZLlyiahf/vczjk/mc5;Llyiahf/vczjk/mc5;Llyiahf/vczjk/sj2;)V

    new-instance v1, Llyiahf/vczjk/pp6;

    const/4 v2, 0x5

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/pp6;-><init>(Llyiahf/vczjk/rp6;I)V

    iput-object v1, v0, Llyiahf/vczjk/rp6;->OooO0o0:Llyiahf/vczjk/t77;

    return-object v9

    :cond_13
    move-object v15, v4

    if-eqz p1, :cond_14

    sget-object v1, Llyiahf/vczjk/nt9;->OooOOo0:Llyiahf/vczjk/nt9;

    filled-new-array {v1}, [Llyiahf/vczjk/nt9;

    move-result-object v1

    invoke-virtual {v2, v1}, Llyiahf/vczjk/w78;->OooO0O0([Llyiahf/vczjk/nt9;)Z

    move-result v1

    if-eqz v1, :cond_14

    invoke-virtual {v2}, Llyiahf/vczjk/w78;->OooOO0O()Llyiahf/vczjk/qt9;

    move-result-object v1

    iget-object v14, v1, Llyiahf/vczjk/qt9;->OooO00o:Llyiahf/vczjk/mc5;

    new-instance v9, Llyiahf/vczjk/kc5;

    invoke-direct/range {v9 .. v15}, Llyiahf/vczjk/z11;-><init>(Ljava/lang/String;Ljava/lang/String;ZLlyiahf/vczjk/mc5;Llyiahf/vczjk/mc5;Llyiahf/vczjk/sj2;)V

    new-instance v1, Llyiahf/vczjk/pp6;

    const/4 v2, 0x0

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/pp6;-><init>(Llyiahf/vczjk/rp6;I)V

    iput-object v1, v0, Llyiahf/vczjk/rp6;->OooO0o0:Llyiahf/vczjk/t77;

    return-object v9

    :cond_14
    if-nez v10, :cond_17

    if-eqz v11, :cond_15

    goto :goto_b

    :cond_15
    if-eqz p1, :cond_16

    const-string v1, "block"

    goto :goto_a

    :cond_16
    const-string v1, "flow"

    :goto_a
    invoke-virtual {v2}, Llyiahf/vczjk/w78;->OooOO0O()Llyiahf/vczjk/qt9;

    move-result-object v2

    new-instance v4, Llyiahf/vczjk/op6;

    const-string v3, "while parsing a "

    const-string v5, " node"

    invoke-static {v3, v1, v5}, Llyiahf/vczjk/u81;->OooOOO0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v5

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v3, "expected the node content, but found \'"

    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2}, Llyiahf/vczjk/qt9;->OooO00o()Llyiahf/vczjk/nt9;

    move-result-object v3

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v3, "\'"

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v7

    const/4 v9, 0x0

    iget-object v8, v2, Llyiahf/vczjk/qt9;->OooO00o:Llyiahf/vczjk/mc5;

    move-object v6, v13

    invoke-direct/range {v4 .. v9}, Llyiahf/vczjk/sc5;-><init>(Ljava/lang/String;Llyiahf/vczjk/mc5;Ljava/lang/String;Llyiahf/vczjk/mc5;Ljava/lang/Exception;)V

    throw v4

    :cond_17
    :goto_b
    new-instance v9, Llyiahf/vczjk/o78;

    new-instance v1, Llyiahf/vczjk/c73;

    const/4 v2, 0x1

    invoke-direct {v1, v2, v12, v5}, Llyiahf/vczjk/c73;-><init>(IZZ)V

    sget-object v16, Llyiahf/vczjk/tj2;->OooOOo0:Llyiahf/vczjk/tj2;

    move-object v14, v13

    const-string v13, ""

    move-object v12, v1

    move-object v15, v8

    invoke-direct/range {v9 .. v16}, Llyiahf/vczjk/o78;-><init>(Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/c73;Ljava/lang/String;Llyiahf/vczjk/mc5;Llyiahf/vczjk/mc5;Llyiahf/vczjk/tj2;)V

    invoke-virtual {v3}, Llyiahf/vczjk/uz5;->OoooOoo()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/t77;

    iput-object v1, v0, Llyiahf/vczjk/rp6;->OooO0o0:Llyiahf/vczjk/t77;

    return-object v9
.end method
