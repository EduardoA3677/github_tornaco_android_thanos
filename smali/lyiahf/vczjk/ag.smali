.class public final Llyiahf/vczjk/ag;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $isLeft:Z

.field final synthetic $minTouchTargetSize:J

.field final synthetic $offsetProvider:Llyiahf/vczjk/v86;

.field final synthetic $semanticsModifier:Llyiahf/vczjk/kl5;


# direct methods
.method public constructor <init>(JZLlyiahf/vczjk/kl5;Llyiahf/vczjk/v86;)V
    .locals 0

    iput-wide p1, p0, Llyiahf/vczjk/ag;->$minTouchTargetSize:J

    iput-boolean p3, p0, Llyiahf/vczjk/ag;->$isLeft:Z

    iput-object p4, p0, Llyiahf/vczjk/ag;->$semanticsModifier:Llyiahf/vczjk/kl5;

    iput-object p5, p0, Llyiahf/vczjk/ag;->$offsetProvider:Llyiahf/vczjk/v86;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 v0, p2, 0x3

    const/4 v1, 0x2

    const/4 v2, 0x1

    const/4 v3, 0x0

    if-eq v0, v1, :cond_0

    move v0, v2

    goto :goto_0

    :cond_0
    move v0, v3

    :goto_0
    and-int/2addr p2, v2

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p2

    if-eqz p2, :cond_a

    iget-wide v0, p0, Llyiahf/vczjk/ag;->$minTouchTargetSize:J

    const-wide v4, 0x7fc000007fc00000L    # 2.247117487993712E307

    cmp-long p2, v0, v4

    sget-object v0, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-eqz p2, :cond_7

    const p2, -0x31ed2b40    # -6.1585408E8f

    invoke-virtual {p1, p2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-boolean p2, p0, Llyiahf/vczjk/ag;->$isLeft:Z

    if-eqz p2, :cond_1

    sget-object p2, Llyiahf/vczjk/cp7;->OooO0O0:Llyiahf/vczjk/vp3;

    goto :goto_1

    :cond_1
    sget-object p2, Llyiahf/vczjk/cp7;->OooO00o:Llyiahf/vczjk/up3;

    :goto_1
    iget-object v4, p0, Llyiahf/vczjk/ag;->$semanticsModifier:Llyiahf/vczjk/kl5;

    iget-wide v5, p0, Llyiahf/vczjk/ag;->$minTouchTargetSize:J

    invoke-static {v5, v6}, Llyiahf/vczjk/ae2;->OooO0O0(J)F

    move-result v5

    iget-wide v6, p0, Llyiahf/vczjk/ag;->$minTouchTargetSize:J

    invoke-static {v6, v7}, Llyiahf/vczjk/ae2;->OooO00o(J)F

    move-result v6

    const/4 v8, 0x0

    const/16 v9, 0xc

    const/4 v7, 0x0

    invoke-static/range {v4 .. v9}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0O(Llyiahf/vczjk/kl5;FFFFI)Llyiahf/vczjk/kl5;

    move-result-object v1

    iget-object v4, p0, Llyiahf/vczjk/ag;->$offsetProvider:Llyiahf/vczjk/v86;

    iget-boolean v5, p0, Llyiahf/vczjk/ag;->$isLeft:Z

    sget-object v6, Llyiahf/vczjk/op3;->OooOo0o:Llyiahf/vczjk/tb0;

    invoke-static {p2, v6, p1, v3}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object p2

    iget v6, p1, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v7

    invoke-static {p1, v1}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v8, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v9, p1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v9, :cond_2

    invoke-virtual {p1, v8}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_2

    :cond_2
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_2
    sget-object v8, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {p2, p1, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object p2, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v7, p1, p2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object p2, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v7, p1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v7, :cond_3

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-static {v7, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_4

    :cond_3
    invoke-static {v6, p1, v6, p2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_4
    sget-object p2, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v1, p1, p2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object p2, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    invoke-virtual {p1, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v1, :cond_5

    if-ne v6, v0, :cond_6

    :cond_5
    new-instance v6, Llyiahf/vczjk/yf;

    invoke-direct {v6, v4}, Llyiahf/vczjk/yf;-><init>(Llyiahf/vczjk/v86;)V

    invoke-virtual {p1, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    check-cast v6, Llyiahf/vczjk/le3;

    const/4 v0, 0x6

    invoke-static {p2, v6, v5, p1, v0}, Llyiahf/vczjk/nqa;->OooOO0O(Llyiahf/vczjk/kl5;Llyiahf/vczjk/le3;ZLlyiahf/vczjk/rf1;I)V

    invoke-virtual {p1, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {p1, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_3

    :cond_7
    const p2, -0x31defe50

    invoke-virtual {p1, p2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p2, p0, Llyiahf/vczjk/ag;->$semanticsModifier:Llyiahf/vczjk/kl5;

    iget-object v1, p0, Llyiahf/vczjk/ag;->$offsetProvider:Llyiahf/vczjk/v86;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    iget-object v2, p0, Llyiahf/vczjk/ag;->$offsetProvider:Llyiahf/vczjk/v86;

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v1, :cond_8

    if-ne v4, v0, :cond_9

    :cond_8
    new-instance v4, Llyiahf/vczjk/zf;

    invoke-direct {v4, v2}, Llyiahf/vczjk/zf;-><init>(Llyiahf/vczjk/v86;)V

    invoke-virtual {p1, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_9
    check-cast v4, Llyiahf/vczjk/le3;

    iget-boolean v0, p0, Llyiahf/vczjk/ag;->$isLeft:Z

    invoke-static {p2, v4, v0, p1, v3}, Llyiahf/vczjk/nqa;->OooOO0O(Llyiahf/vczjk/kl5;Llyiahf/vczjk/le3;ZLlyiahf/vczjk/rf1;I)V

    invoke-virtual {p1, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_3

    :cond_a
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
