.class public final Llyiahf/vczjk/wda;
.super Llyiahf/vczjk/un6;
.source "SourceFile"


# instance fields
.field public final OooOOo:Llyiahf/vczjk/qs5;

.field public final OooOOoo:Llyiahf/vczjk/qs5;

.field public OooOo:I

.field public final OooOo0:Llyiahf/vczjk/qr5;

.field public final OooOo00:Llyiahf/vczjk/fda;

.field public OooOo0O:F

.field public OooOo0o:Llyiahf/vczjk/p21;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fk3;)V
    .locals 3

    invoke-direct {p0}, Llyiahf/vczjk/un6;-><init>()V

    new-instance v0, Llyiahf/vczjk/tq8;

    const-wide/16 v1, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/tq8;-><init>(J)V

    invoke-static {v0}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/wda;->OooOOo:Llyiahf/vczjk/qs5;

    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {v0}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/wda;->OooOOoo:Llyiahf/vczjk/qs5;

    new-instance v0, Llyiahf/vczjk/fda;

    invoke-direct {v0, p1}, Llyiahf/vczjk/fda;-><init>(Llyiahf/vczjk/fk3;)V

    new-instance p1, Llyiahf/vczjk/vda;

    invoke-direct {p1, p0}, Llyiahf/vczjk/vda;-><init>(Llyiahf/vczjk/wda;)V

    iput-object p1, v0, Llyiahf/vczjk/fda;->OooO0o:Llyiahf/vczjk/rm4;

    iput-object v0, p0, Llyiahf/vczjk/wda;->OooOo00:Llyiahf/vczjk/fda;

    const/4 p1, 0x0

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooO0oO(I)Llyiahf/vczjk/qr5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/wda;->OooOo0:Llyiahf/vczjk/qr5;

    const/high16 p1, 0x3f800000    # 1.0f

    iput p1, p0, Llyiahf/vczjk/wda;->OooOo0O:F

    const/4 p1, -0x1

    iput p1, p0, Llyiahf/vczjk/wda;->OooOo:I

    return-void
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/hg2;)V
    .locals 10

    iget-object v0, p0, Llyiahf/vczjk/wda;->OooOo0o:Llyiahf/vczjk/p21;

    iget-object v1, p0, Llyiahf/vczjk/wda;->OooOo00:Llyiahf/vczjk/fda;

    if-nez v0, :cond_0

    iget-object v0, v1, Llyiahf/vczjk/fda;->OooO0oO:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/p21;

    :cond_0
    iget-object v2, p0, Llyiahf/vczjk/wda;->OooOOoo:Llyiahf/vczjk/qs5;

    check-cast v2, Llyiahf/vczjk/fw8;

    invoke-virtual {v2}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Boolean;

    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-interface {p1}, Llyiahf/vczjk/hg2;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/yn4;->OooOOO:Llyiahf/vczjk/yn4;

    if-ne v2, v3, :cond_1

    invoke-interface {p1}, Llyiahf/vczjk/hg2;->o00o0O()J

    move-result-wide v2

    invoke-interface {p1}, Llyiahf/vczjk/hg2;->Ooooo0o()Llyiahf/vczjk/uqa;

    move-result-object v4

    invoke-virtual {v4}, Llyiahf/vczjk/uqa;->OooOo00()J

    move-result-wide v5

    invoke-virtual {v4}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v7

    invoke-interface {v7}, Llyiahf/vczjk/eq0;->OooO0oO()V

    :try_start_0
    iget-object v7, v4, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/vz5;

    const/high16 v8, -0x40800000    # -1.0f

    const/high16 v9, 0x3f800000    # 1.0f

    invoke-virtual {v7, v8, v9, v2, v3}, Llyiahf/vczjk/vz5;->OooOOo0(FFJ)V

    iget v2, p0, Llyiahf/vczjk/wda;->OooOo0O:F

    invoke-virtual {v1, p1, v2, v0}, Llyiahf/vczjk/fda;->OooO0o0(Llyiahf/vczjk/hg2;FLlyiahf/vczjk/p21;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-static {v4, v5, v6}, Llyiahf/vczjk/ix8;->OooOo0O(Llyiahf/vczjk/uqa;J)V

    goto :goto_0

    :catchall_0
    move-exception p1

    invoke-static {v4, v5, v6}, Llyiahf/vczjk/ix8;->OooOo0O(Llyiahf/vczjk/uqa;J)V

    throw p1

    :cond_1
    iget v2, p0, Llyiahf/vczjk/wda;->OooOo0O:F

    invoke-virtual {v1, p1, v2, v0}, Llyiahf/vczjk/fda;->OooO0o0(Llyiahf/vczjk/hg2;FLlyiahf/vczjk/p21;)V

    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/wda;->OooOo0:Llyiahf/vczjk/qr5;

    check-cast p1, Llyiahf/vczjk/bw8;

    invoke-virtual {p1}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result p1

    iput p1, p0, Llyiahf/vczjk/wda;->OooOo:I

    return-void
.end method

.method public final OooO0Oo(F)Z
    .locals 0

    iput p1, p0, Llyiahf/vczjk/wda;->OooOo0O:F

    const/4 p1, 0x1

    return p1
.end method

.method public final OooO0o0(Llyiahf/vczjk/p21;)Z
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/wda;->OooOo0o:Llyiahf/vczjk/p21;

    const/4 p1, 0x1

    return p1
.end method

.method public final OooO0oo()J
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/wda;->OooOOo:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/tq8;

    iget-wide v0, v0, Llyiahf/vczjk/tq8;->OooO00o:J

    return-wide v0
.end method
