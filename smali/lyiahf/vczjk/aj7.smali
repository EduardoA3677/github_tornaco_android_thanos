.class public final Llyiahf/vczjk/aj7;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public OooO00o:I

.field public OooO0O0:Llyiahf/vczjk/sg1;

.field public OooO0OO:Llyiahf/vczjk/d7;

.field public OooO0Oo:Llyiahf/vczjk/ze3;

.field public OooO0o:Llyiahf/vczjk/zr5;

.field public OooO0o0:I

.field public OooO0oO:Llyiahf/vczjk/js5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/sg1;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/aj7;->OooO0O0:Llyiahf/vczjk/sg1;

    return-void
.end method

.method public static OooO00o(Llyiahf/vczjk/w62;Llyiahf/vczjk/js5;)Z
    .locals 2

    const-string v0, "null cannot be cast to non-null type androidx.compose.runtime.DerivedState<kotlin.Any?>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/w62;->OooOOOO:Llyiahf/vczjk/gw8;

    if-nez v0, :cond_0

    sget-object v0, Llyiahf/vczjk/rp3;->OooOo0O:Llyiahf/vczjk/rp3;

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/w62;->OooOo00()Llyiahf/vczjk/u62;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/u62;->OooO0o:Ljava/lang/Object;

    invoke-virtual {p1, p0}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    invoke-interface {v0, v1, p0}, Llyiahf/vczjk/gw8;->OooOO0o(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p0

    xor-int/lit8 p0, p0, 0x1

    return p0
.end method


# virtual methods
.method public final OooO0O0()Z
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/aj7;->OooO0O0:Llyiahf/vczjk/sg1;

    const/4 v1, 0x0

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/aj7;->OooO0OO:Llyiahf/vczjk/d7;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/d7;->OooO00o()Z

    move-result v0

    goto :goto_0

    :cond_0
    move v0, v1

    :goto_0
    if-eqz v0, :cond_1

    const/4 v0, 0x1

    return v0

    :cond_1
    return v1
.end method

.method public final OooO0OO()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/aj7;->OooO0O0:Llyiahf/vczjk/sg1;

    if-eqz v0, :cond_0

    const/4 v1, 0x0

    invoke-virtual {v0, p0, v1}, Llyiahf/vczjk/sg1;->OooOOo0(Llyiahf/vczjk/aj7;Ljava/lang/Object;)Llyiahf/vczjk/m44;

    :cond_0
    return-void
.end method

.method public final OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/m44;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/aj7;->OooO0O0:Llyiahf/vczjk/sg1;

    if-eqz v0, :cond_1

    invoke-virtual {v0, p0, p1}, Llyiahf/vczjk/sg1;->OooOOo0(Llyiahf/vczjk/aj7;Ljava/lang/Object;)Llyiahf/vczjk/m44;

    move-result-object p1

    if-nez p1, :cond_0

    goto :goto_0

    :cond_0
    return-object p1

    :cond_1
    :goto_0
    sget-object p1, Llyiahf/vczjk/m44;->OooOOO0:Llyiahf/vczjk/m44;

    return-object p1
.end method

.method public final OooO0o(Z)V
    .locals 0

    if-eqz p1, :cond_0

    iget p1, p0, Llyiahf/vczjk/aj7;->OooO00o:I

    or-int/lit8 p1, p1, 0x20

    iput p1, p0, Llyiahf/vczjk/aj7;->OooO00o:I

    return-void

    :cond_0
    iget p1, p0, Llyiahf/vczjk/aj7;->OooO00o:I

    and-int/lit8 p1, p1, -0x21

    iput p1, p0, Llyiahf/vczjk/aj7;->OooO00o:I

    return-void
.end method

.method public final OooO0o0()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/aj7;->OooO0O0:Llyiahf/vczjk/sg1;

    if-eqz v0, :cond_0

    const/4 v1, 0x1

    iput-boolean v1, v0, Llyiahf/vczjk/sg1;->OooOoOO:Z

    :cond_0
    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/aj7;->OooO0O0:Llyiahf/vczjk/sg1;

    iput-object v0, p0, Llyiahf/vczjk/aj7;->OooO0o:Llyiahf/vczjk/zr5;

    iput-object v0, p0, Llyiahf/vczjk/aj7;->OooO0oO:Llyiahf/vczjk/js5;

    return-void
.end method
