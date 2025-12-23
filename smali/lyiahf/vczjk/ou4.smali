.class public final Llyiahf/vczjk/ou4;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public OooO00o:Llyiahf/vczjk/xl;


# direct methods
.method public constructor <init>()V
    .locals 9

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    sget-object v1, Llyiahf/vczjk/gda;->OooO00o:Llyiahf/vczjk/n1a;

    const/4 v0, 0x0

    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v2

    move v3, v0

    new-instance v0, Llyiahf/vczjk/xl;

    move v4, v3

    new-instance v3, Llyiahf/vczjk/zl;

    invoke-direct {v3, v4}, Llyiahf/vczjk/zl;-><init>(F)V

    const-wide/high16 v6, -0x8000000000000000L

    const/4 v8, 0x0

    const-wide/high16 v4, -0x8000000000000000L

    invoke-direct/range {v0 .. v8}, Llyiahf/vczjk/xl;-><init>(Llyiahf/vczjk/m1a;Ljava/lang/Object;Llyiahf/vczjk/dm;JJZ)V

    iput-object v0, p0, Llyiahf/vczjk/ou4;->OooO00o:Llyiahf/vczjk/xl;

    return-void
.end method


# virtual methods
.method public final OooO00o(FLlyiahf/vczjk/f62;Llyiahf/vczjk/xr1;)V
    .locals 7

    sget v0, Llyiahf/vczjk/pu4;->OooO00o:F

    invoke-interface {p2, v0}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result p2

    cmpg-float p2, p1, p2

    if-gtz p2, :cond_0

    return-void

    :cond_0
    invoke-static {}, Llyiahf/vczjk/wr6;->OooOOO0()Llyiahf/vczjk/nv8;

    move-result-object p2

    const/4 v0, 0x0

    if-eqz p2, :cond_1

    invoke-virtual {p2}, Llyiahf/vczjk/nv8;->OooO0o0()Llyiahf/vczjk/oe3;

    move-result-object v1

    goto :goto_0

    :cond_1
    move-object v1, v0

    :goto_0
    invoke-static {p2}, Llyiahf/vczjk/wr6;->OooOOOo(Llyiahf/vczjk/nv8;)Llyiahf/vczjk/nv8;

    move-result-object v2

    :try_start_0
    iget-object v3, p0, Llyiahf/vczjk/ou4;->OooO00o:Llyiahf/vczjk/xl;

    iget-object v3, v3, Llyiahf/vczjk/xl;->OooOOO:Llyiahf/vczjk/qs5;

    check-cast v3, Llyiahf/vczjk/fw8;

    invoke-virtual {v3}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    move-result v3

    iget-object v4, p0, Llyiahf/vczjk/ou4;->OooO00o:Llyiahf/vczjk/xl;

    iget-boolean v5, v4, Llyiahf/vczjk/xl;->OooOOo:Z

    const/4 v6, 0x3

    if-eqz v5, :cond_2

    sub-float/2addr v3, p1

    const/16 p1, 0x1e

    const/4 v5, 0x0

    invoke-static {v4, v3, v5, p1}, Llyiahf/vczjk/tg0;->OooOo(Llyiahf/vczjk/xl;FFI)Llyiahf/vczjk/xl;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/ou4;->OooO00o:Llyiahf/vczjk/xl;

    new-instance p1, Llyiahf/vczjk/mu4;

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/mu4;-><init>(Llyiahf/vczjk/ou4;Llyiahf/vczjk/yo1;)V

    invoke-static {p3, v0, v0, p1, v6}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    goto :goto_1

    :catchall_0
    move-exception p1

    goto :goto_2

    :cond_2
    new-instance v3, Llyiahf/vczjk/xl;

    sget-object v4, Llyiahf/vczjk/gda;->OooO00o:Llyiahf/vczjk/n1a;

    neg-float p1, p1

    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object p1

    const/16 v5, 0x3c

    invoke-direct {v3, v4, p1, v0, v5}, Llyiahf/vczjk/xl;-><init>(Llyiahf/vczjk/m1a;Ljava/lang/Object;Llyiahf/vczjk/dm;I)V

    iput-object v3, p0, Llyiahf/vczjk/ou4;->OooO00o:Llyiahf/vczjk/xl;

    new-instance p1, Llyiahf/vczjk/nu4;

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/nu4;-><init>(Llyiahf/vczjk/ou4;Llyiahf/vczjk/yo1;)V

    invoke-static {p3, v0, v0, p1, v6}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :goto_1
    invoke-static {p2, v2, v1}, Llyiahf/vczjk/wr6;->OooOo0O(Llyiahf/vczjk/nv8;Llyiahf/vczjk/nv8;Llyiahf/vczjk/oe3;)V

    return-void

    :goto_2
    invoke-static {p2, v2, v1}, Llyiahf/vczjk/wr6;->OooOo0O(Llyiahf/vczjk/nv8;Llyiahf/vczjk/nv8;Llyiahf/vczjk/oe3;)V

    throw p1
.end method
