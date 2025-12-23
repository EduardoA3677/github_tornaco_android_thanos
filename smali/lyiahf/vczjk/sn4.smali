.class public final Llyiahf/vczjk/sn4;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/rm4;

.field public OooO0O0:Landroid/graphics/Matrix;

.field public final OooO0OO:[F

.field public final OooO0Oo:[F

.field public OooO0o:Z

.field public OooO0o0:Z

.field public OooO0oO:Z

.field public OooO0oo:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ze3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    check-cast p1, Llyiahf/vczjk/rm4;

    iput-object p1, p0, Llyiahf/vczjk/sn4;->OooO00o:Llyiahf/vczjk/rm4;

    invoke-static {}, Llyiahf/vczjk/ze5;->OooO00o()[F

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/sn4;->OooO0OO:[F

    invoke-static {}, Llyiahf/vczjk/ze5;->OooO00o()[F

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/sn4;->OooO0Oo:[F

    const/4 p1, 0x1

    iput-boolean p1, p0, Llyiahf/vczjk/sn4;->OooO0oO:Z

    iput-boolean p1, p0, Llyiahf/vczjk/sn4;->OooO0oo:Z

    return-void
.end method


# virtual methods
.method public final OooO00o(Ljava/lang/Object;)[F
    .locals 2

    iget-boolean v0, p0, Llyiahf/vczjk/sn4;->OooO0o:Z

    iget-object v1, p0, Llyiahf/vczjk/sn4;->OooO0Oo:[F

    if-eqz v0, :cond_0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/sn4;->OooO0O0(Ljava/lang/Object;)[F

    move-result-object p1

    invoke-static {p1, v1}, Llyiahf/vczjk/so8;->OooOooo([F[F)Z

    move-result p1

    iput-boolean p1, p0, Llyiahf/vczjk/sn4;->OooO0oO:Z

    const/4 p1, 0x0

    iput-boolean p1, p0, Llyiahf/vczjk/sn4;->OooO0o:Z

    :cond_0
    iget-boolean p1, p0, Llyiahf/vczjk/sn4;->OooO0oO:Z

    if-eqz p1, :cond_1

    return-object v1

    :cond_1
    const/4 p1, 0x0

    return-object p1
.end method

.method public final OooO0O0(Ljava/lang/Object;)[F
    .locals 3

    iget-boolean v0, p0, Llyiahf/vczjk/sn4;->OooO0o0:Z

    iget-object v1, p0, Llyiahf/vczjk/sn4;->OooO0OO:[F

    if-nez v0, :cond_0

    return-object v1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/sn4;->OooO0O0:Landroid/graphics/Matrix;

    if-nez v0, :cond_1

    new-instance v0, Landroid/graphics/Matrix;

    invoke-direct {v0}, Landroid/graphics/Matrix;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/sn4;->OooO0O0:Landroid/graphics/Matrix;

    :cond_1
    iget-object v2, p0, Llyiahf/vczjk/sn4;->OooO00o:Llyiahf/vczjk/rm4;

    invoke-interface {v2, p1, v0}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-static {v0, v1}, Llyiahf/vczjk/os9;->OoooO(Landroid/graphics/Matrix;[F)V

    const/4 p1, 0x0

    iput-boolean p1, p0, Llyiahf/vczjk/sn4;->OooO0o0:Z

    invoke-static {v1}, Llyiahf/vczjk/m6a;->o0OoOo0([F)Z

    move-result p1

    iput-boolean p1, p0, Llyiahf/vczjk/sn4;->OooO0oo:Z

    return-object v1
.end method

.method public final OooO0OO()V
    .locals 1

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/sn4;->OooO0o0:Z

    iput-boolean v0, p0, Llyiahf/vczjk/sn4;->OooO0o:Z

    return-void
.end method
