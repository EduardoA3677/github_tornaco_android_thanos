.class public final Llyiahf/vczjk/tz8;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/gi;

.field public final OooO0O0:Llyiahf/vczjk/qs5;


# direct methods
.method public constructor <init>()V
    .locals 5

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/gi;

    new-instance v1, Llyiahf/vczjk/p86;

    const-wide/16 v2, 0x0

    invoke-direct {v1, v2, v3}, Llyiahf/vczjk/p86;-><init>(J)V

    sget-object v2, Llyiahf/vczjk/gda;->OooO0o:Llyiahf/vczjk/n1a;

    const/16 v3, 0xc

    const/4 v4, 0x0

    invoke-direct {v0, v1, v2, v4, v3}, Llyiahf/vczjk/gi;-><init>(Ljava/lang/Object;Llyiahf/vczjk/n1a;Ljava/lang/Object;I)V

    iput-object v0, p0, Llyiahf/vczjk/tz8;->OooO00o:Llyiahf/vczjk/gi;

    invoke-static {v4}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/tz8;->OooO0O0:Llyiahf/vczjk/qs5;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/f54;JLlyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 16

    move-object/from16 v0, p0

    move-object/from16 v1, p4

    instance-of v2, v1, Llyiahf/vczjk/sz8;

    if-eqz v2, :cond_0

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/sz8;

    iget v3, v2, Llyiahf/vczjk/sz8;->label:I

    const/high16 v4, -0x80000000

    and-int v5, v3, v4

    if-eqz v5, :cond_0

    sub-int/2addr v3, v4

    iput v3, v2, Llyiahf/vczjk/sz8;->label:I

    :goto_0
    move-object v7, v2

    goto :goto_1

    :cond_0
    new-instance v2, Llyiahf/vczjk/sz8;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/sz8;-><init>(Llyiahf/vczjk/tz8;Llyiahf/vczjk/zo1;)V

    goto :goto_0

    :goto_1
    iget-object v1, v7, Llyiahf/vczjk/sz8;->result:Ljava/lang/Object;

    sget-object v2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v3, v7, Llyiahf/vczjk/sz8;->label:I

    iget-object v9, v0, Llyiahf/vczjk/tz8;->OooO0O0:Llyiahf/vczjk/qs5;

    const/4 v4, 0x2

    const/4 v5, 0x1

    if-eqz v3, :cond_3

    if-eq v3, v5, :cond_2

    if-ne v3, v4, :cond_1

    invoke-static {v1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_4

    :cond_1
    new-instance v1, Ljava/lang/IllegalStateException;

    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {v1, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_2
    invoke-static {v1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_3
    invoke-static {v1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object v1, v9

    check-cast v1, Llyiahf/vczjk/fw8;

    move-object/from16 v3, p1

    invoke-virtual {v1, v3}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    new-instance v1, Llyiahf/vczjk/p86;

    move-wide/from16 v10, p2

    invoke-direct {v1, v10, v11}, Llyiahf/vczjk/p86;-><init>(J)V

    iput v5, v7, Llyiahf/vczjk/sz8;->label:I

    iget-object v3, v0, Llyiahf/vczjk/tz8;->OooO00o:Llyiahf/vczjk/gi;

    invoke-virtual {v3, v1, v7}, Llyiahf/vczjk/gi;->OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v2, :cond_4

    goto :goto_3

    :cond_4
    :goto_2
    new-instance v1, Llyiahf/vczjk/p86;

    const-wide/16 v10, 0x0

    invoke-direct {v1, v10, v11}, Llyiahf/vczjk/p86;-><init>(J)V

    const/high16 v3, 0x3f000000    # 0.5f

    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v6

    int-to-long v10, v6

    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v3

    int-to-long v12, v3

    const/16 v3, 0x20

    shl-long/2addr v10, v3

    const-wide v14, 0xffffffffL

    and-long/2addr v12, v14

    or-long/2addr v10, v12

    new-instance v3, Llyiahf/vczjk/p86;

    invoke-direct {v3, v10, v11}, Llyiahf/vczjk/p86;-><init>(J)V

    const/4 v6, 0x0

    const/high16 v8, 0x43c80000    # 400.0f

    invoke-static {v6, v8, v3, v5}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    move-result-object v5

    iput v4, v7, Llyiahf/vczjk/sz8;->label:I

    const/4 v6, 0x0

    const/16 v8, 0xc

    iget-object v3, v0, Llyiahf/vczjk/tz8;->OooO00o:Llyiahf/vczjk/gi;

    move-object v4, v1

    invoke-static/range {v3 .. v8}, Llyiahf/vczjk/gi;->OooO0O0(Llyiahf/vczjk/gi;Ljava/lang/Object;Llyiahf/vczjk/wl;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;I)Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v2, :cond_5

    :goto_3
    return-object v2

    :cond_5
    :goto_4
    check-cast v9, Llyiahf/vczjk/fw8;

    const/4 v1, 0x0

    invoke-virtual {v9, v1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
