.class public final Llyiahf/vczjk/jr3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/dx2;


# static fields
.field public static final OooO0o:Llyiahf/vczjk/pm0;

.field public static final OooO0oO:Llyiahf/vczjk/pm0;


# instance fields
.field public final OooO00o:Ljava/lang/String;

.field public final OooO0O0:Llyiahf/vczjk/hf6;

.field public final OooO0OO:Llyiahf/vczjk/sc9;

.field public final OooO0Oo:Llyiahf/vczjk/sc9;

.field public final OooO0o0:Z


# direct methods
.method static constructor <clinit>()V
    .locals 15

    new-instance v0, Llyiahf/vczjk/pm0;

    const/4 v10, 0x0

    const/4 v13, 0x0

    const/4 v1, 0x1

    const/4 v2, 0x1

    const/4 v3, -0x1

    const/4 v4, -0x1

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, -0x1

    const/4 v9, -0x1

    const/4 v11, 0x0

    const/4 v12, 0x0

    invoke-direct/range {v0 .. v13}, Llyiahf/vczjk/pm0;-><init>(ZZIIZZZIIZZZLjava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/jr3;->OooO0o:Llyiahf/vczjk/pm0;

    new-instance v1, Llyiahf/vczjk/pm0;

    const/4 v11, 0x1

    const/4 v14, 0x0

    const/4 v2, 0x1

    const/4 v3, 0x0

    const/4 v4, -0x1

    const/4 v5, -0x1

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, -0x1

    const/4 v10, -0x1

    const/4 v12, 0x0

    const/4 v13, 0x0

    invoke-direct/range {v1 .. v14}, Llyiahf/vczjk/pm0;-><init>(ZZIIZZZIIZZZLjava/lang/String;)V

    sput-object v1, Llyiahf/vczjk/jr3;->OooO0oO:Llyiahf/vczjk/pm0;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Llyiahf/vczjk/hf6;Llyiahf/vczjk/sc9;Llyiahf/vczjk/sc9;Z)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/jr3;->OooO00o:Ljava/lang/String;

    iput-object p2, p0, Llyiahf/vczjk/jr3;->OooO0O0:Llyiahf/vczjk/hf6;

    iput-object p3, p0, Llyiahf/vczjk/jr3;->OooO0OO:Llyiahf/vczjk/sc9;

    iput-object p4, p0, Llyiahf/vczjk/jr3;->OooO0Oo:Llyiahf/vczjk/sc9;

    iput-boolean p5, p0, Llyiahf/vczjk/jr3;->OooO0o0:Z

    return-void
.end method

.method public static OooO0Oo(Ljava/lang/String;Llyiahf/vczjk/uf5;)Ljava/lang/String;
    .locals 3

    const/4 v0, 0x0

    if-eqz p1, :cond_0

    iget-object p1, p1, Llyiahf/vczjk/uf5;->OooO00o:Ljava/lang/String;

    goto :goto_0

    :cond_0
    move-object p1, v0

    :goto_0
    if-eqz p1, :cond_1

    const/4 v1, 0x0

    const-string v2, "text/plain"

    invoke-static {p1, v2, v1}, Llyiahf/vczjk/g79;->Oooo00o(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v1

    if-eqz v1, :cond_2

    :cond_1
    invoke-static {}, Landroid/webkit/MimeTypeMap;->getSingleton()Landroid/webkit/MimeTypeMap;

    move-result-object v1

    invoke-static {v1, p0}, Llyiahf/vczjk/OooOOO0;->OooO0O0(Landroid/webkit/MimeTypeMap;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    if-eqz p0, :cond_2

    return-object p0

    :cond_2
    if-eqz p1, :cond_3

    const/16 p0, 0x3b

    invoke-static {p0, p1, p1}, Llyiahf/vczjk/z69;->o0OoOo0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_3
    return-object v0
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 13

    instance-of v0, p1, Llyiahf/vczjk/ir3;

    if-eqz v0, :cond_0

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/ir3;

    iget v1, v0, Llyiahf/vczjk/ir3;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/ir3;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/ir3;

    check-cast p1, Llyiahf/vczjk/zo1;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/ir3;-><init>(Llyiahf/vczjk/jr3;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p1, v0, Llyiahf/vczjk/ir3;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/ir3;->label:I

    const-string v3, "response body == null"

    const/4 v4, 0x0

    const/4 v5, 0x2

    const/4 v6, 0x1

    if-eqz v2, :cond_3

    if-eq v2, v6, :cond_2

    if-ne v2, v5, :cond_1

    iget-object v1, v0, Llyiahf/vczjk/ir3;->L$2:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/is7;

    iget-object v2, v0, Llyiahf/vczjk/ir3;->L$1:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/bi7;

    iget-object v0, v0, Llyiahf/vczjk/ir3;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/jr3;

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto/16 :goto_8

    :catch_0
    move-exception p1

    goto/16 :goto_a

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    iget-object v2, v0, Llyiahf/vczjk/ir3;->L$2:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/zm0;

    iget-object v6, v0, Llyiahf/vczjk/ir3;->L$1:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/bi7;

    iget-object v7, v0, Llyiahf/vczjk/ir3;->L$0:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/jr3;

    :try_start_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    move-object v12, v6

    move-object v6, v2

    move-object v2, v12

    goto/16 :goto_3

    :catch_1
    move-exception p1

    goto/16 :goto_b

    :cond_3
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/jr3;->OooO0O0:Llyiahf/vczjk/hf6;

    iget-object v2, p1, Llyiahf/vczjk/hf6;->OooOOO:Llyiahf/vczjk/vm0;

    invoke-virtual {v2}, Llyiahf/vczjk/vm0;->OooO00o()Z

    move-result v2

    iget-object v7, p0, Llyiahf/vczjk/jr3;->OooO00o:Ljava/lang/String;

    if-eqz v2, :cond_5

    iget-object v2, p0, Llyiahf/vczjk/jr3;->OooO0Oo:Llyiahf/vczjk/sc9;

    invoke-virtual {v2}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ci7;

    if-eqz v2, :cond_5

    iget-object p1, p1, Llyiahf/vczjk/hf6;->OooO:Ljava/lang/String;

    if-nez p1, :cond_4

    move-object p1, v7

    :cond_4
    sget-object v8, Llyiahf/vczjk/jm0;->OooOOOO:Llyiahf/vczjk/jm0;

    invoke-static {p1}, Llyiahf/vczjk/ws7;->OooO(Ljava/lang/String;)Llyiahf/vczjk/jm0;

    move-result-object p1

    const-string v8, "SHA-256"

    invoke-virtual {p1, v8}, Llyiahf/vczjk/jm0;->OooO0OO(Ljava/lang/String;)Llyiahf/vczjk/jm0;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/jm0;->OooO0o()Ljava/lang/String;

    move-result-object p1

    iget-object v2, v2, Llyiahf/vczjk/ci7;->OooO0O0:Llyiahf/vczjk/cc2;

    invoke-virtual {v2, p1}, Llyiahf/vczjk/cc2;->OooOOOO(Ljava/lang/String;)Llyiahf/vczjk/zb2;

    move-result-object p1

    if-eqz p1, :cond_5

    new-instance v2, Llyiahf/vczjk/bi7;

    invoke-direct {v2, p1}, Llyiahf/vczjk/bi7;-><init>(Llyiahf/vczjk/zb2;)V

    goto :goto_1

    :cond_5
    move-object v2, v4

    :goto_1
    if-eqz v2, :cond_b

    :try_start_2
    invoke-virtual {p0}, Llyiahf/vczjk/jr3;->OooO0OO()Llyiahf/vczjk/ez2;

    move-result-object p1

    iget-object v8, v2, Llyiahf/vczjk/bi7;->OooOOO0:Llyiahf/vczjk/zb2;

    iget-boolean v9, v8, Llyiahf/vczjk/zb2;->OooOOO:Z

    if-nez v9, :cond_a

    iget-object v8, v8, Llyiahf/vczjk/zb2;->OooOOO0:Llyiahf/vczjk/yb2;

    iget-object v8, v8, Llyiahf/vczjk/yb2;->OooO0OO:Ljava/util/ArrayList;

    const/4 v9, 0x0

    invoke-virtual {v8, v9}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/zp6;

    invoke-virtual {p1, v8}, Llyiahf/vczjk/ez2;->OooO0oO(Llyiahf/vczjk/zp6;)Llyiahf/vczjk/o62;

    move-result-object p1

    iget-object p1, p1, Llyiahf/vczjk/o62;->OooO0o0:Ljava/lang/Object;

    check-cast p1, Ljava/lang/Long;

    if-nez p1, :cond_6

    goto :goto_2

    :cond_6
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    move-result-wide v8

    const-wide/16 v10, 0x0

    cmp-long p1, v8, v10

    if-nez p1, :cond_7

    new-instance p1, Llyiahf/vczjk/by8;

    invoke-virtual {p0, v2}, Llyiahf/vczjk/jr3;->OooO0oO(Llyiahf/vczjk/bi7;)Llyiahf/vczjk/ky2;

    move-result-object v0

    invoke-static {v7, v4}, Llyiahf/vczjk/jr3;->OooO0Oo(Ljava/lang/String;Llyiahf/vczjk/uf5;)Ljava/lang/String;

    move-result-object v1

    sget-object v3, Llyiahf/vczjk/zx1;->OooOOOO:Llyiahf/vczjk/zx1;

    invoke-direct {p1, v0, v1, v3}, Llyiahf/vczjk/by8;-><init>(Llyiahf/vczjk/nv3;Ljava/lang/String;Llyiahf/vczjk/zx1;)V

    return-object p1

    :catch_2
    move-exception p1

    move-object v6, v2

    goto/16 :goto_b

    :cond_7
    :goto_2
    iget-boolean p1, p0, Llyiahf/vczjk/jr3;->OooO0o0:Z

    if-eqz p1, :cond_8

    new-instance p1, Llyiahf/vczjk/ym0;

    invoke-virtual {p0}, Llyiahf/vczjk/jr3;->OooO0o0()Llyiahf/vczjk/lr;

    move-result-object v8

    invoke-virtual {p0, v2}, Llyiahf/vczjk/jr3;->OooO0o(Llyiahf/vczjk/bi7;)Llyiahf/vczjk/xm0;

    move-result-object v9

    invoke-direct {p1, v8, v9}, Llyiahf/vczjk/ym0;-><init>(Llyiahf/vczjk/lr;Llyiahf/vczjk/xm0;)V

    invoke-virtual {p1}, Llyiahf/vczjk/ym0;->OooO00o()Llyiahf/vczjk/zm0;

    move-result-object p1

    iget-object v8, p1, Llyiahf/vczjk/zm0;->OooO00o:Llyiahf/vczjk/lr;
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_2

    if-nez v8, :cond_c

    iget-object v8, p1, Llyiahf/vczjk/zm0;->OooO0O0:Llyiahf/vczjk/xm0;

    if-eqz v8, :cond_c

    :try_start_3
    new-instance p1, Llyiahf/vczjk/by8;

    invoke-virtual {p0, v2}, Llyiahf/vczjk/jr3;->OooO0oO(Llyiahf/vczjk/bi7;)Llyiahf/vczjk/ky2;

    move-result-object v0

    iget-object v1, v8, Llyiahf/vczjk/xm0;->OooO0O0:Ljava/lang/Object;

    invoke-interface {v1}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/uf5;

    invoke-static {v7, v1}, Llyiahf/vczjk/jr3;->OooO0Oo(Ljava/lang/String;Llyiahf/vczjk/uf5;)Ljava/lang/String;

    move-result-object v1

    sget-object v3, Llyiahf/vczjk/zx1;->OooOOOO:Llyiahf/vczjk/zx1;

    invoke-direct {p1, v0, v1, v3}, Llyiahf/vczjk/by8;-><init>(Llyiahf/vczjk/nv3;Ljava/lang/String;Llyiahf/vczjk/zx1;)V

    return-object p1

    :cond_8
    new-instance p1, Llyiahf/vczjk/by8;

    invoke-virtual {p0, v2}, Llyiahf/vczjk/jr3;->OooO0oO(Llyiahf/vczjk/bi7;)Llyiahf/vczjk/ky2;

    move-result-object v0

    invoke-virtual {p0, v2}, Llyiahf/vczjk/jr3;->OooO0o(Llyiahf/vczjk/bi7;)Llyiahf/vczjk/xm0;

    move-result-object v1

    if-eqz v1, :cond_9

    iget-object v1, v1, Llyiahf/vczjk/xm0;->OooO0O0:Ljava/lang/Object;

    invoke-interface {v1}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v1

    move-object v4, v1

    check-cast v4, Llyiahf/vczjk/uf5;

    :cond_9
    invoke-static {v7, v4}, Llyiahf/vczjk/jr3;->OooO0Oo(Ljava/lang/String;Llyiahf/vczjk/uf5;)Ljava/lang/String;

    move-result-object v1

    sget-object v3, Llyiahf/vczjk/zx1;->OooOOOO:Llyiahf/vczjk/zx1;

    invoke-direct {p1, v0, v1, v3}, Llyiahf/vczjk/by8;-><init>(Llyiahf/vczjk/nv3;Ljava/lang/String;Llyiahf/vczjk/zx1;)V

    return-object p1

    :cond_a
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "snapshot is closed"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_b
    new-instance p1, Llyiahf/vczjk/ym0;

    invoke-virtual {p0}, Llyiahf/vczjk/jr3;->OooO0o0()Llyiahf/vczjk/lr;

    move-result-object v7

    invoke-direct {p1, v7, v4}, Llyiahf/vczjk/ym0;-><init>(Llyiahf/vczjk/lr;Llyiahf/vczjk/xm0;)V

    invoke-virtual {p1}, Llyiahf/vczjk/ym0;->OooO00o()Llyiahf/vczjk/zm0;

    move-result-object p1

    :cond_c
    iget-object v7, p1, Llyiahf/vczjk/zm0;->OooO00o:Llyiahf/vczjk/lr;

    invoke-static {v7}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iput-object p0, v0, Llyiahf/vczjk/ir3;->L$0:Ljava/lang/Object;

    iput-object v2, v0, Llyiahf/vczjk/ir3;->L$1:Ljava/lang/Object;

    iput-object p1, v0, Llyiahf/vczjk/ir3;->L$2:Ljava/lang/Object;

    iput v6, v0, Llyiahf/vczjk/ir3;->label:I

    invoke-virtual {p0, v7, v0}, Llyiahf/vczjk/jr3;->OooO0O0(Llyiahf/vczjk/lr;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v6

    if-ne v6, v1, :cond_d

    goto/16 :goto_7

    :cond_d
    move-object v7, v6

    move-object v6, p1

    move-object p1, v7

    move-object v7, p0

    :goto_3
    check-cast p1, Llyiahf/vczjk/is7;

    sget-object v8, Llyiahf/vczjk/OooOOO0;->OooO00o:Landroid/graphics/Bitmap$Config;

    iget-object v8, p1, Llyiahf/vczjk/is7;->OooOOoo:Llyiahf/vczjk/ks7;
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_2

    if-eqz v8, :cond_15

    :try_start_4
    iget-object v9, v6, Llyiahf/vczjk/zm0;->OooO00o:Llyiahf/vczjk/lr;

    iget-object v6, v6, Llyiahf/vczjk/zm0;->OooO0O0:Llyiahf/vczjk/xm0;

    invoke-virtual {v7, v2, v9, p1, v6}, Llyiahf/vczjk/jr3;->OooO0oo(Llyiahf/vczjk/bi7;Llyiahf/vczjk/lr;Llyiahf/vczjk/is7;Llyiahf/vczjk/xm0;)Llyiahf/vczjk/bi7;

    move-result-object v2
    :try_end_4
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_3

    iget-object v6, v7, Llyiahf/vczjk/jr3;->OooO00o:Ljava/lang/String;

    if-eqz v2, :cond_f

    :try_start_5
    new-instance v0, Llyiahf/vczjk/by8;

    invoke-virtual {v7, v2}, Llyiahf/vczjk/jr3;->OooO0oO(Llyiahf/vczjk/bi7;)Llyiahf/vczjk/ky2;

    move-result-object v1

    invoke-virtual {v7, v2}, Llyiahf/vczjk/jr3;->OooO0o(Llyiahf/vczjk/bi7;)Llyiahf/vczjk/xm0;

    move-result-object v3

    if-eqz v3, :cond_e

    iget-object v3, v3, Llyiahf/vczjk/xm0;->OooO0O0:Ljava/lang/Object;

    invoke-interface {v3}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v3

    move-object v4, v3

    check-cast v4, Llyiahf/vczjk/uf5;

    goto :goto_5

    :goto_4
    move-object v1, p1

    move-object p1, v0

    goto/16 :goto_a

    :cond_e
    :goto_5
    invoke-static {v6, v4}, Llyiahf/vczjk/jr3;->OooO0Oo(Ljava/lang/String;Llyiahf/vczjk/uf5;)Ljava/lang/String;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/zx1;->OooOOOo:Llyiahf/vczjk/zx1;

    invoke-direct {v0, v1, v3, v4}, Llyiahf/vczjk/by8;-><init>(Llyiahf/vczjk/nv3;Ljava/lang/String;Llyiahf/vczjk/zx1;)V

    return-object v0

    :catch_3
    move-exception v0

    goto :goto_4

    :cond_f
    invoke-virtual {v8}, Llyiahf/vczjk/ks7;->OooOOOO()Llyiahf/vczjk/nj0;

    move-result-object v9

    const-wide/16 v10, 0x1

    invoke-interface {v9, v10, v11}, Llyiahf/vczjk/nj0;->Oooooo(J)Z

    move-result v9

    if-eqz v9, :cond_11

    new-instance v0, Llyiahf/vczjk/by8;

    invoke-virtual {v8}, Llyiahf/vczjk/ks7;->OooOOOO()Llyiahf/vczjk/nj0;

    move-result-object v1

    iget-object v3, v7, Llyiahf/vczjk/jr3;->OooO0O0:Llyiahf/vczjk/hf6;

    iget-object v3, v3, Llyiahf/vczjk/hf6;->OooO00o:Landroid/content/Context;

    new-instance v3, Llyiahf/vczjk/tx8;

    invoke-direct {v3, v1, v4}, Llyiahf/vczjk/tx8;-><init>(Llyiahf/vczjk/nj0;Llyiahf/vczjk/qqa;)V

    invoke-virtual {v8}, Llyiahf/vczjk/ks7;->OooO0oO()Llyiahf/vczjk/uf5;

    move-result-object v1

    invoke-static {v6, v1}, Llyiahf/vczjk/jr3;->OooO0Oo(Ljava/lang/String;Llyiahf/vczjk/uf5;)Ljava/lang/String;

    move-result-object v1

    iget-object v4, p1, Llyiahf/vczjk/is7;->OooOo00:Llyiahf/vczjk/is7;

    if-eqz v4, :cond_10

    sget-object v4, Llyiahf/vczjk/zx1;->OooOOOo:Llyiahf/vczjk/zx1;

    goto :goto_6

    :cond_10
    sget-object v4, Llyiahf/vczjk/zx1;->OooOOOO:Llyiahf/vczjk/zx1;

    :goto_6
    invoke-direct {v0, v3, v1, v4}, Llyiahf/vczjk/by8;-><init>(Llyiahf/vczjk/nv3;Ljava/lang/String;Llyiahf/vczjk/zx1;)V

    return-object v0

    :cond_11
    invoke-static {p1}, Llyiahf/vczjk/OooOOO0;->OooO00o(Ljava/io/Closeable;)V

    invoke-virtual {v7}, Llyiahf/vczjk/jr3;->OooO0o0()Llyiahf/vczjk/lr;

    move-result-object v6

    iput-object v7, v0, Llyiahf/vczjk/ir3;->L$0:Ljava/lang/Object;

    iput-object v2, v0, Llyiahf/vczjk/ir3;->L$1:Ljava/lang/Object;

    iput-object p1, v0, Llyiahf/vczjk/ir3;->L$2:Ljava/lang/Object;

    iput v5, v0, Llyiahf/vczjk/ir3;->label:I

    invoke-virtual {v7, v6, v0}, Llyiahf/vczjk/jr3;->OooO0O0(Llyiahf/vczjk/lr;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v0
    :try_end_5
    .catch Ljava/lang/Exception; {:try_start_5 .. :try_end_5} :catch_3

    if-ne v0, v1, :cond_12

    :goto_7
    return-object v1

    :cond_12
    move-object v1, p1

    move-object p1, v0

    move-object v0, v7

    :goto_8
    :try_start_6
    check-cast p1, Llyiahf/vczjk/is7;
    :try_end_6
    .catch Ljava/lang/Exception; {:try_start_6 .. :try_end_6} :catch_0

    :try_start_7
    sget-object v1, Llyiahf/vczjk/OooOOO0;->OooO00o:Landroid/graphics/Bitmap$Config;

    iget-object v1, p1, Llyiahf/vczjk/is7;->OooOOoo:Llyiahf/vczjk/ks7;

    if-eqz v1, :cond_14

    new-instance v3, Llyiahf/vczjk/by8;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v1}, Llyiahf/vczjk/ks7;->OooOOOO()Llyiahf/vczjk/nj0;

    move-result-object v5

    iget-object v6, v0, Llyiahf/vczjk/jr3;->OooO0O0:Llyiahf/vczjk/hf6;

    iget-object v6, v6, Llyiahf/vczjk/hf6;->OooO00o:Landroid/content/Context;

    new-instance v6, Llyiahf/vczjk/tx8;

    invoke-direct {v6, v5, v4}, Llyiahf/vczjk/tx8;-><init>(Llyiahf/vczjk/nj0;Llyiahf/vczjk/qqa;)V

    iget-object v0, v0, Llyiahf/vczjk/jr3;->OooO00o:Ljava/lang/String;

    invoke-virtual {v1}, Llyiahf/vczjk/ks7;->OooO0oO()Llyiahf/vczjk/uf5;

    move-result-object v1

    invoke-static {v0, v1}, Llyiahf/vczjk/jr3;->OooO0Oo(Ljava/lang/String;Llyiahf/vczjk/uf5;)Ljava/lang/String;

    move-result-object v0

    iget-object v1, p1, Llyiahf/vczjk/is7;->OooOo00:Llyiahf/vczjk/is7;

    if-eqz v1, :cond_13

    sget-object v1, Llyiahf/vczjk/zx1;->OooOOOo:Llyiahf/vczjk/zx1;

    goto :goto_9

    :cond_13
    sget-object v1, Llyiahf/vczjk/zx1;->OooOOOO:Llyiahf/vczjk/zx1;

    :goto_9
    invoke-direct {v3, v6, v0, v1}, Llyiahf/vczjk/by8;-><init>(Llyiahf/vczjk/nv3;Ljava/lang/String;Llyiahf/vczjk/zx1;)V

    return-object v3

    :cond_14
    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-direct {v0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
    :try_end_7
    .catch Ljava/lang/Exception; {:try_start_7 .. :try_end_7} :catch_3

    :goto_a
    :try_start_8
    invoke-static {v1}, Llyiahf/vczjk/OooOOO0;->OooO00o(Ljava/io/Closeable;)V

    throw p1

    :cond_15
    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-direct {p1, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
    :try_end_8
    .catch Ljava/lang/Exception; {:try_start_8 .. :try_end_8} :catch_2

    :goto_b
    if-eqz v6, :cond_16

    invoke-static {v6}, Llyiahf/vczjk/OooOOO0;->OooO00o(Ljava/io/Closeable;)V

    :cond_16
    throw p1
.end method

.method public final OooO0O0(Llyiahf/vczjk/lr;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 5

    instance-of v0, p2, Llyiahf/vczjk/hr3;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/hr3;

    iget v1, v0, Llyiahf/vczjk/hr3;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/hr3;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/hr3;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/hr3;-><init>(Llyiahf/vczjk/jr3;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/hr3;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/hr3;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    sget-object p2, Llyiahf/vczjk/OooOOO0;->OooO00o:Landroid/graphics/Bitmap$Config;

    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    move-result-object p2

    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    move-result-object v2

    invoke-static {p2, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p2

    iget-object v2, p0, Llyiahf/vczjk/jr3;->OooO0OO:Llyiahf/vczjk/sc9;

    const-string v4, "request"

    if-eqz p2, :cond_4

    iget-object p2, p0, Llyiahf/vczjk/jr3;->OooO0O0:Llyiahf/vczjk/hf6;

    iget-object p2, p2, Llyiahf/vczjk/hf6;->OooOOOO:Llyiahf/vczjk/vm0;

    invoke-virtual {p2}, Llyiahf/vczjk/vm0;->OooO00o()Z

    move-result p2

    if-nez p2, :cond_3

    invoke-virtual {v2}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/vn0;

    check-cast p2, Llyiahf/vczjk/e96;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/mh7;

    invoke-direct {v0, p2, p1}, Llyiahf/vczjk/mh7;-><init>(Llyiahf/vczjk/e96;Llyiahf/vczjk/lr;)V

    invoke-virtual {v0}, Llyiahf/vczjk/mh7;->OooO0o0()Llyiahf/vczjk/is7;

    move-result-object p1

    goto :goto_2

    :cond_3
    new-instance p1, Landroid/os/NetworkOnMainThreadException;

    invoke-direct {p1}, Landroid/os/NetworkOnMainThreadException;-><init>()V

    throw p1

    :cond_4
    invoke-virtual {v2}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/vn0;

    check-cast p2, Llyiahf/vczjk/e96;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v2, Llyiahf/vczjk/mh7;

    invoke-direct {v2, p2, p1}, Llyiahf/vczjk/mh7;-><init>(Llyiahf/vczjk/e96;Llyiahf/vczjk/lr;)V

    iput v3, v0, Llyiahf/vczjk/hr3;->label:I

    new-instance p1, Llyiahf/vczjk/yp0;

    invoke-static {v0}, Llyiahf/vczjk/dn8;->ooOO(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p2

    invoke-direct {p1, v3, p2}, Llyiahf/vczjk/yp0;-><init>(ILlyiahf/vczjk/yo1;)V

    invoke-virtual {p1}, Llyiahf/vczjk/yp0;->OooOOoo()V

    new-instance p2, Llyiahf/vczjk/o0oOO;

    const/4 v0, 0x3

    invoke-direct {p2, v0, v2, p1}, Llyiahf/vczjk/o0oOO;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v2, p2}, Llyiahf/vczjk/mh7;->OooO0Oo(Llyiahf/vczjk/io0;)V

    invoke-virtual {p1, p2}, Llyiahf/vczjk/yp0;->OooOo0(Llyiahf/vczjk/oe3;)V

    invoke-virtual {p1}, Llyiahf/vczjk/yp0;->OooOOo()Ljava/lang/Object;

    move-result-object p2

    if-ne p2, v1, :cond_5

    return-object v1

    :cond_5
    :goto_1
    move-object p1, p2

    check-cast p1, Llyiahf/vczjk/is7;

    :goto_2
    invoke-virtual {p1}, Llyiahf/vczjk/is7;->OooO0oO()Z

    move-result p2

    if-nez p2, :cond_7

    const/16 p2, 0x130

    iget v0, p1, Llyiahf/vczjk/is7;->OooOOOo:I

    if-eq v0, p2, :cond_7

    iget-object p2, p1, Llyiahf/vczjk/is7;->OooOOoo:Llyiahf/vczjk/ks7;

    if-eqz p2, :cond_6

    invoke-static {p2}, Llyiahf/vczjk/OooOOO0;->OooO00o(Ljava/io/Closeable;)V

    :cond_6
    new-instance p2, Llyiahf/vczjk/br3;

    invoke-direct {p2, p1}, Llyiahf/vczjk/br3;-><init>(Llyiahf/vczjk/is7;)V

    throw p2

    :cond_7
    return-object p1
.end method

.method public final OooO0OO()Llyiahf/vczjk/ez2;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/jr3;->OooO0Oo:Llyiahf/vczjk/sc9;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    check-cast v0, Llyiahf/vczjk/ci7;

    iget-object v0, v0, Llyiahf/vczjk/ci7;->OooO00o:Llyiahf/vczjk/we4;

    return-object v0
.end method

.method public final OooO0o(Llyiahf/vczjk/bi7;)Llyiahf/vczjk/xm0;
    .locals 3

    const/4 v0, 0x0

    :try_start_0
    invoke-virtual {p0}, Llyiahf/vczjk/jr3;->OooO0OO()Llyiahf/vczjk/ez2;

    move-result-object v1

    iget-object p1, p1, Llyiahf/vczjk/bi7;->OooOOO0:Llyiahf/vczjk/zb2;

    iget-boolean v2, p1, Llyiahf/vczjk/zb2;->OooOOO:Z

    if-nez v2, :cond_1

    iget-object p1, p1, Llyiahf/vczjk/zb2;->OooOOO0:Llyiahf/vczjk/yb2;

    iget-object p1, p1, Llyiahf/vczjk/yb2;->OooO0OO:Ljava/util/ArrayList;

    const/4 v2, 0x0

    invoke-virtual {p1, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/zp6;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/ez2;->OooOO0O(Llyiahf/vczjk/zp6;)Llyiahf/vczjk/rx8;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/ng0;->OooOOO(Llyiahf/vczjk/rx8;)Llyiahf/vczjk/ih7;

    move-result-object p1
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    :try_start_1
    new-instance v1, Llyiahf/vczjk/xm0;

    invoke-direct {v1, p1}, Llyiahf/vczjk/xm0;-><init>(Llyiahf/vczjk/ih7;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :try_start_2
    invoke-virtual {p1}, Llyiahf/vczjk/ih7;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    move-object p1, v0

    goto :goto_1

    :catchall_0
    move-exception p1

    goto :goto_1

    :catchall_1
    move-exception v1

    :try_start_3
    invoke-virtual {p1}, Llyiahf/vczjk/ih7;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    goto :goto_0

    :catchall_2
    move-exception p1

    :try_start_4
    invoke-static {v1, p1}, Llyiahf/vczjk/cp7;->OooO0oO(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    :goto_0
    move-object p1, v1

    move-object v1, v0

    :goto_1
    if-nez p1, :cond_0

    return-object v1

    :cond_0
    throw p1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v1, "snapshot is closed"

    invoke-direct {p1, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_0

    :catch_0
    return-object v0
.end method

.method public final OooO0o0()Llyiahf/vczjk/lr;
    .locals 6

    new-instance v0, Llyiahf/vczjk/mi;

    invoke-direct {v0}, Llyiahf/vczjk/mi;-><init>()V

    iget-object v1, p0, Llyiahf/vczjk/jr3;->OooO00o:Ljava/lang/String;

    const-string v2, "url"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "ws:"

    const/4 v3, 0x1

    invoke-static {v1, v2, v3}, Llyiahf/vczjk/g79;->Oooo00o(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v2

    const-string v4, "this as java.lang.String).substring(startIndex)"

    if-eqz v2, :cond_0

    const/4 v2, 0x3

    invoke-virtual {v1, v2}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object v1

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "http:"

    invoke-virtual {v2, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    goto :goto_0

    :cond_0
    const-string v2, "wss:"

    invoke-static {v1, v2, v3}, Llyiahf/vczjk/g79;->Oooo00o(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v2

    if-eqz v2, :cond_1

    const/4 v2, 0x4

    invoke-virtual {v1, v2}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object v1

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "https:"

    invoke-virtual {v2, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    :cond_1
    :goto_0
    const-string v2, "<this>"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v2, Llyiahf/vczjk/kr3;

    const/4 v3, 0x0

    invoke-direct {v2, v3}, Llyiahf/vczjk/kr3;-><init>(I)V

    const/4 v3, 0x0

    invoke-virtual {v2, v3, v1}, Llyiahf/vczjk/kr3;->OooO0o0(Llyiahf/vczjk/lr3;Ljava/lang/String;)V

    invoke-virtual {v2}, Llyiahf/vczjk/kr3;->OooO0O0()Llyiahf/vczjk/lr3;

    move-result-object v1

    iput-object v1, v0, Llyiahf/vczjk/mi;->OooOOO0:Ljava/lang/Object;

    iget-object v1, p0, Llyiahf/vczjk/jr3;->OooO0O0:Llyiahf/vczjk/hf6;

    iget-object v2, v1, Llyiahf/vczjk/hf6;->OooOO0:Llyiahf/vczjk/vm3;

    const-string v3, "headers"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v2}, Llyiahf/vczjk/vm3;->OooO0o()Llyiahf/vczjk/oO0OOo0o;

    move-result-object v2

    iput-object v2, v0, Llyiahf/vczjk/mi;->OooOOOO:Ljava/lang/Object;

    iget-object v2, v1, Llyiahf/vczjk/hf6;->OooOO0O:Llyiahf/vczjk/bf9;

    iget-object v2, v2, Llyiahf/vczjk/bf9;->OooO00o:Ljava/util/Map;

    invoke-interface {v2}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    move-result-object v2

    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_2

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/util/Map$Entry;

    invoke-interface {v3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v4

    const-string v5, "null cannot be cast to non-null type java.lang.Class<kotlin.Any>"

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v4, Ljava/lang/Class;

    invoke-interface {v3}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v3

    invoke-virtual {v0, v4, v3}, Llyiahf/vczjk/mi;->OoooO(Ljava/lang/Class;Ljava/lang/Object;)V

    goto :goto_1

    :cond_2
    iget-object v2, v1, Llyiahf/vczjk/hf6;->OooOOO:Llyiahf/vczjk/vm0;

    invoke-virtual {v2}, Llyiahf/vczjk/vm0;->OooO00o()Z

    move-result v3

    iget-object v1, v1, Llyiahf/vczjk/hf6;->OooOOOO:Llyiahf/vczjk/vm0;

    invoke-virtual {v1}, Llyiahf/vczjk/vm0;->OooO00o()Z

    move-result v1

    if-nez v1, :cond_3

    if-eqz v3, :cond_3

    sget-object v1, Llyiahf/vczjk/pm0;->OooOOOO:Llyiahf/vczjk/pm0;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/mi;->OooO0o0(Llyiahf/vczjk/pm0;)V

    goto :goto_2

    :cond_3
    if-eqz v1, :cond_5

    if-nez v3, :cond_5

    invoke-virtual {v2}, Llyiahf/vczjk/vm0;->OooO0O0()Z

    move-result v1

    if-eqz v1, :cond_4

    sget-object v1, Llyiahf/vczjk/pm0;->OooOOO:Llyiahf/vczjk/pm0;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/mi;->OooO0o0(Llyiahf/vczjk/pm0;)V

    goto :goto_2

    :cond_4
    sget-object v1, Llyiahf/vczjk/jr3;->OooO0o:Llyiahf/vczjk/pm0;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/mi;->OooO0o0(Llyiahf/vczjk/pm0;)V

    goto :goto_2

    :cond_5
    if-nez v1, :cond_6

    if-nez v3, :cond_6

    sget-object v1, Llyiahf/vczjk/jr3;->OooO0oO:Llyiahf/vczjk/pm0;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/mi;->OooO0o0(Llyiahf/vczjk/pm0;)V

    :cond_6
    :goto_2
    invoke-virtual {v0}, Llyiahf/vczjk/mi;->OooO0Oo()Llyiahf/vczjk/lr;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0oO(Llyiahf/vczjk/bi7;)Llyiahf/vczjk/ky2;
    .locals 4

    iget-object v0, p1, Llyiahf/vczjk/bi7;->OooOOO0:Llyiahf/vczjk/zb2;

    iget-boolean v1, v0, Llyiahf/vczjk/zb2;->OooOOO:Z

    if-nez v1, :cond_1

    iget-object v0, v0, Llyiahf/vczjk/zb2;->OooOOO0:Llyiahf/vczjk/yb2;

    iget-object v0, v0, Llyiahf/vczjk/yb2;->OooO0OO:Ljava/util/ArrayList;

    const/4 v1, 0x1

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/zp6;

    invoke-virtual {p0}, Llyiahf/vczjk/jr3;->OooO0OO()Llyiahf/vczjk/ez2;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/jr3;->OooO0O0:Llyiahf/vczjk/hf6;

    iget-object v2, v2, Llyiahf/vczjk/hf6;->OooO:Ljava/lang/String;

    if-nez v2, :cond_0

    iget-object v2, p0, Llyiahf/vczjk/jr3;->OooO00o:Ljava/lang/String;

    :cond_0
    new-instance v3, Llyiahf/vczjk/ky2;

    invoke-direct {v3, v0, v1, v2, p1}, Llyiahf/vczjk/ky2;-><init>(Llyiahf/vczjk/zp6;Llyiahf/vczjk/ez2;Ljava/lang/String;Llyiahf/vczjk/bi7;)V

    return-object v3

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "snapshot is closed"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooO0oo(Llyiahf/vczjk/bi7;Llyiahf/vczjk/lr;Llyiahf/vczjk/is7;Llyiahf/vczjk/xm0;)Llyiahf/vczjk/bi7;
    .locals 4

    const/4 v0, 0x1

    iget-object v1, p0, Llyiahf/vczjk/jr3;->OooO0O0:Llyiahf/vczjk/hf6;

    iget-object v1, v1, Llyiahf/vczjk/hf6;->OooOOO:Llyiahf/vczjk/vm0;

    invoke-virtual {v1}, Llyiahf/vczjk/vm0;->OooO0O0()Z

    move-result v1

    const/4 v2, 0x0

    if-eqz v1, :cond_a

    iget-boolean v1, p0, Llyiahf/vczjk/jr3;->OooO0o0:Z

    if-eqz v1, :cond_1

    invoke-virtual {p2}, Llyiahf/vczjk/lr;->OooOO0()Llyiahf/vczjk/pm0;

    move-result-object p2

    iget-boolean p2, p2, Llyiahf/vczjk/pm0;->OooO0O0:Z

    if-nez p2, :cond_a

    iget-object p2, p3, Llyiahf/vczjk/is7;->OooOoO:Llyiahf/vczjk/pm0;

    if-nez p2, :cond_0

    sget-object p2, Llyiahf/vczjk/pm0;->OooOOO:Llyiahf/vczjk/pm0;

    iget-object p2, p3, Llyiahf/vczjk/is7;->OooOOo:Llyiahf/vczjk/vm3;

    invoke-static {p2}, Llyiahf/vczjk/tg0;->OooOooo(Llyiahf/vczjk/vm3;)Llyiahf/vczjk/pm0;

    move-result-object p2

    iput-object p2, p3, Llyiahf/vczjk/is7;->OooOoO:Llyiahf/vczjk/pm0;

    :cond_0
    iget-boolean p2, p2, Llyiahf/vczjk/pm0;->OooO0O0:Z

    if-nez p2, :cond_a

    const-string p2, "Vary"

    iget-object v1, p3, Llyiahf/vczjk/is7;->OooOOo:Llyiahf/vczjk/vm3;

    invoke-virtual {v1, p2}, Llyiahf/vczjk/vm3;->OooO00o(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    const-string v1, "*"

    invoke-static {p2, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p2

    if-nez p2, :cond_a

    :cond_1
    if-eqz p1, :cond_2

    iget-object p1, p1, Llyiahf/vczjk/bi7;->OooOOO0:Llyiahf/vczjk/zb2;

    iget-object p2, p1, Llyiahf/vczjk/zb2;->OooOOOO:Llyiahf/vczjk/cc2;

    monitor-enter p2

    :try_start_0
    invoke-virtual {p1}, Llyiahf/vczjk/zb2;->close()V

    iget-object p1, p1, Llyiahf/vczjk/zb2;->OooOOO0:Llyiahf/vczjk/yb2;

    iget-object p1, p1, Llyiahf/vczjk/yb2;->OooO00o:Ljava/lang/String;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/cc2;->OooO0oO(Ljava/lang/String;)Llyiahf/vczjk/zu1;

    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit p2

    if-eqz p1, :cond_4

    new-instance p2, Llyiahf/vczjk/h87;

    invoke-direct {p2, p1, v0}, Llyiahf/vczjk/h87;-><init>(Ljava/lang/Object;I)V

    goto :goto_0

    :catchall_0
    move-exception p1

    monitor-exit p2

    throw p1

    :cond_2
    iget-object p1, p0, Llyiahf/vczjk/jr3;->OooO0Oo:Llyiahf/vczjk/sc9;

    invoke-virtual {p1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ci7;

    if-eqz p1, :cond_4

    iget-object p2, p0, Llyiahf/vczjk/jr3;->OooO0O0:Llyiahf/vczjk/hf6;

    iget-object p2, p2, Llyiahf/vczjk/hf6;->OooO:Ljava/lang/String;

    if-nez p2, :cond_3

    iget-object p2, p0, Llyiahf/vczjk/jr3;->OooO00o:Ljava/lang/String;

    :cond_3
    iget-object p1, p1, Llyiahf/vczjk/ci7;->OooO0O0:Llyiahf/vczjk/cc2;

    sget-object v1, Llyiahf/vczjk/jm0;->OooOOOO:Llyiahf/vczjk/jm0;

    invoke-static {p2}, Llyiahf/vczjk/ws7;->OooO(Ljava/lang/String;)Llyiahf/vczjk/jm0;

    move-result-object p2

    const-string v1, "SHA-256"

    invoke-virtual {p2, v1}, Llyiahf/vczjk/jm0;->OooO0OO(Ljava/lang/String;)Llyiahf/vczjk/jm0;

    move-result-object p2

    invoke-virtual {p2}, Llyiahf/vczjk/jm0;->OooO0o()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p1, p2}, Llyiahf/vczjk/cc2;->OooO0oO(Ljava/lang/String;)Llyiahf/vczjk/zu1;

    move-result-object p1

    if-eqz p1, :cond_4

    new-instance p2, Llyiahf/vczjk/h87;

    invoke-direct {p2, p1, v0}, Llyiahf/vczjk/h87;-><init>(Ljava/lang/Object;I)V

    goto :goto_0

    :cond_4
    move-object p2, v2

    :goto_0
    if-nez p2, :cond_5

    goto/16 :goto_c

    :cond_5
    const/4 p1, 0x0

    :try_start_1
    iget v1, p3, Llyiahf/vczjk/is7;->OooOOOo:I

    const/16 v3, 0x130

    if-ne v1, v3, :cond_7

    if-eqz p4, :cond_7

    invoke-virtual {p3}, Llyiahf/vczjk/is7;->OooOOOO()Llyiahf/vczjk/gs7;

    move-result-object v0

    iget-object p4, p4, Llyiahf/vczjk/xm0;->OooO0o:Llyiahf/vczjk/vm3;

    iget-object v1, p3, Llyiahf/vczjk/is7;->OooOOo:Llyiahf/vczjk/vm3;

    invoke-static {p4, v1}, Llyiahf/vczjk/t51;->OooOo00(Llyiahf/vczjk/vm3;Llyiahf/vczjk/vm3;)Llyiahf/vczjk/vm3;

    move-result-object p4

    invoke-virtual {p4}, Llyiahf/vczjk/vm3;->OooO0o()Llyiahf/vczjk/oO0OOo0o;

    move-result-object p4

    iput-object p4, v0, Llyiahf/vczjk/gs7;->OooO0o:Llyiahf/vczjk/oO0OOo0o;

    invoke-virtual {v0}, Llyiahf/vczjk/gs7;->OooO00o()Llyiahf/vczjk/is7;

    move-result-object p4

    invoke-virtual {p0}, Llyiahf/vczjk/jr3;->OooO0OO()Llyiahf/vczjk/ez2;

    move-result-object v0

    iget-object v1, p2, Llyiahf/vczjk/h87;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/zu1;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/zu1;->OooO0o0(I)Llyiahf/vczjk/zp6;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ez2;->OooOO0(Llyiahf/vczjk/zp6;)Llyiahf/vczjk/rq8;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/ng0;->OooOOO0(Llyiahf/vczjk/rq8;)Llyiahf/vczjk/hh7;

    move-result-object v0
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_4

    :try_start_2
    new-instance v1, Llyiahf/vczjk/xm0;

    invoke-direct {v1, p4}, Llyiahf/vczjk/xm0;-><init>(Llyiahf/vczjk/is7;)V

    invoke-virtual {v1, v0}, Llyiahf/vczjk/xm0;->OooO00o(Llyiahf/vczjk/hh7;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    :try_start_3
    invoke-virtual {v0}, Llyiahf/vczjk/hh7;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    goto :goto_3

    :catchall_1
    move-exception v2

    goto :goto_3

    :goto_1
    move-object v2, p4

    goto :goto_2

    :catchall_2
    move-exception p4

    goto :goto_1

    :goto_2
    :try_start_4
    invoke-virtual {v0}, Llyiahf/vczjk/hh7;->close()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    goto :goto_3

    :catchall_3
    move-exception p4

    :try_start_5
    invoke-static {v2, p4}, Llyiahf/vczjk/cp7;->OooO0oO(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    :goto_3
    if-nez v2, :cond_6

    goto/16 :goto_9

    :cond_6
    throw v2

    :catchall_4
    move-exception p1

    goto/16 :goto_b

    :catch_0
    move-exception p4

    goto/16 :goto_a

    :cond_7
    invoke-virtual {p0}, Llyiahf/vczjk/jr3;->OooO0OO()Llyiahf/vczjk/ez2;

    move-result-object p4

    iget-object v1, p2, Llyiahf/vczjk/h87;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/zu1;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/zu1;->OooO0o0(I)Llyiahf/vczjk/zp6;

    move-result-object v1

    invoke-virtual {p4, v1}, Llyiahf/vczjk/ez2;->OooOO0(Llyiahf/vczjk/zp6;)Llyiahf/vczjk/rq8;

    move-result-object p4

    invoke-static {p4}, Llyiahf/vczjk/ng0;->OooOOO0(Llyiahf/vczjk/rq8;)Llyiahf/vczjk/hh7;

    move-result-object p4
    :try_end_5
    .catch Ljava/lang/Exception; {:try_start_5 .. :try_end_5} :catch_0
    .catchall {:try_start_5 .. :try_end_5} :catchall_4

    :try_start_6
    new-instance v1, Llyiahf/vczjk/xm0;

    invoke-direct {v1, p3}, Llyiahf/vczjk/xm0;-><init>(Llyiahf/vczjk/is7;)V

    invoke-virtual {v1, p4}, Llyiahf/vczjk/xm0;->OooO00o(Llyiahf/vczjk/hh7;)V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_6

    :try_start_7
    invoke-virtual {p4}, Llyiahf/vczjk/hh7;->close()V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_5

    move-object p4, v2

    goto :goto_5

    :catchall_5
    move-exception p4

    goto :goto_5

    :catchall_6
    move-exception v1

    :try_start_8
    invoke-virtual {p4}, Llyiahf/vczjk/hh7;->close()V
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_7

    goto :goto_4

    :catchall_7
    move-exception p4

    :try_start_9
    invoke-static {v1, p4}, Llyiahf/vczjk/cp7;->OooO0oO(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    :goto_4
    move-object p4, v1

    :goto_5
    if-nez p4, :cond_9

    invoke-virtual {p0}, Llyiahf/vczjk/jr3;->OooO0OO()Llyiahf/vczjk/ez2;

    move-result-object p4

    iget-object v1, p2, Llyiahf/vczjk/h87;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/zu1;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zu1;->OooO0o0(I)Llyiahf/vczjk/zp6;

    move-result-object v0

    invoke-virtual {p4, v0}, Llyiahf/vczjk/ez2;->OooOO0(Llyiahf/vczjk/zp6;)Llyiahf/vczjk/rq8;

    move-result-object p4

    invoke-static {p4}, Llyiahf/vczjk/ng0;->OooOOO0(Llyiahf/vczjk/rq8;)Llyiahf/vczjk/hh7;

    move-result-object p4
    :try_end_9
    .catch Ljava/lang/Exception; {:try_start_9 .. :try_end_9} :catch_0
    .catchall {:try_start_9 .. :try_end_9} :catchall_4

    :try_start_a
    iget-object v0, p3, Llyiahf/vczjk/is7;->OooOOoo:Llyiahf/vczjk/ks7;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v0}, Llyiahf/vczjk/ks7;->OooOOOO()Llyiahf/vczjk/nj0;

    move-result-object v0

    invoke-interface {v0, p4}, Llyiahf/vczjk/nj0;->o00o0O(Llyiahf/vczjk/mj0;)J
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_9

    :try_start_b
    invoke-virtual {p4}, Llyiahf/vczjk/hh7;->close()V
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_8

    goto :goto_8

    :catchall_8
    move-exception v2

    goto :goto_8

    :goto_6
    move-object v2, v0

    goto :goto_7

    :catchall_9
    move-exception v0

    goto :goto_6

    :goto_7
    :try_start_c
    invoke-virtual {p4}, Llyiahf/vczjk/hh7;->close()V
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_a

    goto :goto_8

    :catchall_a
    move-exception p4

    :try_start_d
    invoke-static {v2, p4}, Llyiahf/vczjk/cp7;->OooO0oO(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    :goto_8
    if-nez v2, :cond_8

    :goto_9
    invoke-virtual {p2}, Llyiahf/vczjk/h87;->OooO0O0()Llyiahf/vczjk/bi7;

    move-result-object p1
    :try_end_d
    .catch Ljava/lang/Exception; {:try_start_d .. :try_end_d} :catch_0
    .catchall {:try_start_d .. :try_end_d} :catchall_4

    invoke-static {p3}, Llyiahf/vczjk/OooOOO0;->OooO00o(Ljava/io/Closeable;)V

    return-object p1

    :cond_8
    :try_start_e
    throw v2

    :cond_9
    throw p4
    :try_end_e
    .catch Ljava/lang/Exception; {:try_start_e .. :try_end_e} :catch_0
    .catchall {:try_start_e .. :try_end_e} :catchall_4

    :goto_a
    :try_start_f
    sget-object v0, Llyiahf/vczjk/OooOOO0;->OooO00o:Landroid/graphics/Bitmap$Config;
    :try_end_f
    .catchall {:try_start_f .. :try_end_f} :catchall_4

    :try_start_10
    iget-object p2, p2, Llyiahf/vczjk/h87;->OooOOO:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/zu1;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zu1;->OooO0O0(Z)V
    :try_end_10
    .catch Ljava/lang/Exception; {:try_start_10 .. :try_end_10} :catch_1
    .catchall {:try_start_10 .. :try_end_10} :catchall_4

    :catch_1
    :try_start_11
    throw p4
    :try_end_11
    .catchall {:try_start_11 .. :try_end_11} :catchall_4

    :goto_b
    invoke-static {p3}, Llyiahf/vczjk/OooOOO0;->OooO00o(Ljava/io/Closeable;)V

    throw p1

    :cond_a
    if-eqz p1, :cond_b

    invoke-static {p1}, Llyiahf/vczjk/OooOOO0;->OooO00o(Ljava/io/Closeable;)V

    :cond_b
    :goto_c
    return-object v2
.end method
