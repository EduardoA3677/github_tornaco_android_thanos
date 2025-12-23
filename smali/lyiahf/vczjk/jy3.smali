.class public final Llyiahf/vczjk/jy3;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/ws5;

.field public final OooO0O0:Llyiahf/vczjk/qs5;

.field public OooO0OO:J

.field public final OooO0Oo:Llyiahf/vczjk/qs5;


# direct methods
.method public constructor <init>(Ljava/lang/String;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p1, Llyiahf/vczjk/ws5;

    const/16 v0, 0x10

    new-array v0, v0, [Llyiahf/vczjk/dy3;

    invoke-direct {p1, v0}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    iput-object p1, p0, Llyiahf/vczjk/jy3;->OooO00o:Llyiahf/vczjk/ws5;

    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/jy3;->OooO0O0:Llyiahf/vczjk/qs5;

    const-wide/high16 v0, -0x8000000000000000L

    iput-wide v0, p0, Llyiahf/vczjk/jy3;->OooO0OO:J

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/jy3;->OooO0Oo:Llyiahf/vczjk/qs5;

    return-void
.end method


# virtual methods
.method public final OooO00o(ILlyiahf/vczjk/rf1;)V
    .locals 6

    check-cast p2, Llyiahf/vczjk/zf1;

    const v0, -0x12f4f699

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v0, p1, 0x6

    const/4 v1, 0x2

    if-nez v0, :cond_1

    invoke-virtual {p2, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    move v0, v1

    :goto_0
    or-int/2addr v0, p1

    goto :goto_1

    :cond_1
    move v0, p1

    :goto_1
    and-int/lit8 v2, v0, 0x3

    const/4 v3, 0x1

    const/4 v4, 0x0

    if-eq v2, v1, :cond_2

    move v1, v3

    goto :goto_2

    :cond_2
    move v1, v4

    :goto_2
    and-int/2addr v0, v3

    invoke-virtual {p2, v0, v1}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v0

    if-eqz v0, :cond_8

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    const/4 v2, 0x0

    if-ne v0, v1, :cond_3

    invoke-static {v2}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v0

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    check-cast v0, Llyiahf/vczjk/qs5;

    iget-object v3, p0, Llyiahf/vczjk/jy3;->OooO0Oo:Llyiahf/vczjk/qs5;

    check-cast v3, Llyiahf/vczjk/fw8;

    invoke-virtual {v3}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/Boolean;

    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v3

    if-nez v3, :cond_5

    iget-object v3, p0, Llyiahf/vczjk/jy3;->OooO0O0:Llyiahf/vczjk/qs5;

    check-cast v3, Llyiahf/vczjk/fw8;

    invoke-virtual {v3}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/Boolean;

    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v3

    if-eqz v3, :cond_4

    goto :goto_3

    :cond_4
    const v0, 0x669880b8

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {p2, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_4

    :cond_5
    :goto_3
    const v3, 0x668357d5

    invoke-virtual {p2, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {p2, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v3, :cond_6

    if-ne v5, v1, :cond_7

    :cond_6
    new-instance v5, Llyiahf/vczjk/hy3;

    invoke-direct {v5, v0, p0, v2}, Llyiahf/vczjk/hy3;-><init>(Llyiahf/vczjk/qs5;Llyiahf/vczjk/jy3;Llyiahf/vczjk/yo1;)V

    invoke-virtual {p2, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    check-cast v5, Llyiahf/vczjk/ze3;

    invoke-static {p0, p2, v5}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-virtual {p2, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_4

    :cond_8
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_4
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p2

    if-eqz p2, :cond_9

    new-instance v0, Llyiahf/vczjk/iy3;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/iy3;-><init>(Llyiahf/vczjk/jy3;I)V

    iput-object v0, p2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_9
    return-void
.end method
