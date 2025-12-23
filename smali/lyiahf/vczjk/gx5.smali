.class public final Llyiahf/vczjk/gx5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Z

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Z

.field public final synthetic OooOOOo:Ljava/lang/Object;

.field public final synthetic OooOOo:Ljava/lang/Object;

.field public final synthetic OooOOo0:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yw5;ZZLlyiahf/vczjk/p13;Llyiahf/vczjk/ze3;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/gx5;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/gx5;->OooOOOo:Ljava/lang/Object;

    iput-boolean p2, p0, Llyiahf/vczjk/gx5;->OooOOO:Z

    iput-boolean p3, p0, Llyiahf/vczjk/gx5;->OooOOOO:Z

    iput-object p4, p0, Llyiahf/vczjk/gx5;->OooOOo0:Ljava/lang/Object;

    iput-object p5, p0, Llyiahf/vczjk/gx5;->OooOOo:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(ZZLlyiahf/vczjk/rr5;Llyiahf/vczjk/ei9;Llyiahf/vczjk/qj8;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/gx5;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Llyiahf/vczjk/gx5;->OooOOO:Z

    iput-boolean p2, p0, Llyiahf/vczjk/gx5;->OooOOOO:Z

    iput-object p3, p0, Llyiahf/vczjk/gx5;->OooOOOo:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/gx5;->OooOOo0:Ljava/lang/Object;

    iput-object p5, p0, Llyiahf/vczjk/gx5;->OooOOo:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    iget v0, p0, Llyiahf/vczjk/gx5;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 v0, p2, 0x3

    const/4 v1, 0x2

    const/4 v2, 0x1

    if-eq v0, v1, :cond_0

    move v0, v2

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    and-int/2addr p2, v2

    move-object v10, p1

    check-cast v10, Llyiahf/vczjk/zf1;

    invoke-virtual {v10, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p1

    if-eqz p1, :cond_1

    sget-object v1, Llyiahf/vczjk/xf6;->OooO00o:Llyiahf/vczjk/xf6;

    iget-object p1, p0, Llyiahf/vczjk/gx5;->OooOOo0:Ljava/lang/Object;

    move-object v6, p1

    check-cast v6, Llyiahf/vczjk/ei9;

    const/high16 v11, 0x6000000

    const/16 v12, 0xc8

    iget-boolean v2, p0, Llyiahf/vczjk/gx5;->OooOOO:Z

    iget-boolean v3, p0, Llyiahf/vczjk/gx5;->OooOOOO:Z

    iget-object p1, p0, Llyiahf/vczjk/gx5;->OooOOOo:Ljava/lang/Object;

    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/rr5;

    const/4 v5, 0x0

    iget-object p1, p0, Llyiahf/vczjk/gx5;->OooOOo:Ljava/lang/Object;

    move-object v7, p1

    check-cast v7, Llyiahf/vczjk/qj8;

    const/4 v8, 0x0

    const/4 v9, 0x0

    invoke-virtual/range {v1 .. v12}, Llyiahf/vczjk/xf6;->OooO00o(ZZLlyiahf/vczjk/n24;Llyiahf/vczjk/hl5;Llyiahf/vczjk/ei9;Llyiahf/vczjk/qj8;FFLlyiahf/vczjk/rf1;II)V

    goto :goto_1

    :cond_1
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 v0, p2, 0x3

    const/4 v1, 0x2

    const/4 v2, 0x1

    if-eq v0, v1, :cond_2

    move v0, v2

    goto :goto_2

    :cond_2
    const/4 v0, 0x0

    :goto_2
    and-int/2addr p2, v2

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/zf1;

    invoke-virtual {v5, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p1

    if-eqz p1, :cond_5

    sget-object p1, Llyiahf/vczjk/px5;->OooO:Llyiahf/vczjk/p6a;

    invoke-static {p1, v5}, Llyiahf/vczjk/q6a;->OooO00o(Llyiahf/vczjk/p6a;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/rn9;

    move-result-object v3

    iget-boolean p1, p0, Llyiahf/vczjk/gx5;->OooOOOO:Z

    iget-object p2, p0, Llyiahf/vczjk/gx5;->OooOOOo:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/yw5;

    if-nez p1, :cond_3

    iget-wide p1, p2, Llyiahf/vczjk/yw5;->OooO0oO:J

    goto :goto_3

    :cond_3
    iget-boolean p1, p0, Llyiahf/vczjk/gx5;->OooOOO:Z

    if-eqz p1, :cond_4

    iget-wide p1, p2, Llyiahf/vczjk/yw5;->OooO0O0:J

    goto :goto_3

    :cond_4
    iget-wide p1, p2, Llyiahf/vczjk/yw5;->OooO0o0:J

    :goto_3
    iget-object v0, p0, Llyiahf/vczjk/gx5;->OooOOo0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/p13;

    invoke-static {p1, p2, v0, v5}, Llyiahf/vczjk/pq8;->OooO00o(JLlyiahf/vczjk/wl;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/p29;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/n21;

    iget-wide v1, p1, Llyiahf/vczjk/n21;->OooO00o:J

    iget-object p1, p0, Llyiahf/vczjk/gx5;->OooOOo:Ljava/lang/Object;

    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/ze3;

    const/4 v6, 0x0

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/tp6;->OooO0Oo(JLlyiahf/vczjk/rn9;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    goto :goto_4

    :cond_5
    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_4
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
