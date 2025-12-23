.class public final Llyiahf/vczjk/mu5;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public OooO:Z

.field public final OooO00o:Llyiahf/vczjk/ku5;

.field public final OooO0O0:Llyiahf/vczjk/av5;

.field public final OooO0OO:Landroid/os/Bundle;

.field public OooO0Oo:Llyiahf/vczjk/jy4;

.field public final OooO0o:Ljava/lang/String;

.field public final OooO0o0:Llyiahf/vczjk/tu5;

.field public final OooO0oO:Landroid/os/Bundle;

.field public final OooO0oo:Llyiahf/vczjk/f68;

.field public final OooOO0:Llyiahf/vczjk/wy4;

.field public OooOO0O:Llyiahf/vczjk/jy4;

.field public final OooOO0o:Llyiahf/vczjk/i68;

.field public final OooOOO0:Llyiahf/vczjk/sc9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ku5;)V
    .locals 3

    const-string v0, "entry"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/mu5;->OooO00o:Llyiahf/vczjk/ku5;

    iget-object v0, p1, Llyiahf/vczjk/ku5;->OooOOO:Llyiahf/vczjk/av5;

    iput-object v0, p0, Llyiahf/vczjk/mu5;->OooO0O0:Llyiahf/vczjk/av5;

    iget-object v0, p1, Llyiahf/vczjk/ku5;->OooOOOO:Landroid/os/Bundle;

    iput-object v0, p0, Llyiahf/vczjk/mu5;->OooO0OO:Landroid/os/Bundle;

    iget-object v0, p1, Llyiahf/vczjk/ku5;->OooOOOo:Llyiahf/vczjk/jy4;

    iput-object v0, p0, Llyiahf/vczjk/mu5;->OooO0Oo:Llyiahf/vczjk/jy4;

    iget-object v0, p1, Llyiahf/vczjk/ku5;->OooOOo0:Llyiahf/vczjk/tu5;

    iput-object v0, p0, Llyiahf/vczjk/mu5;->OooO0o0:Llyiahf/vczjk/tu5;

    iget-object v0, p1, Llyiahf/vczjk/ku5;->OooOOo:Ljava/lang/String;

    iput-object v0, p0, Llyiahf/vczjk/mu5;->OooO0o:Ljava/lang/String;

    iget-object v0, p1, Llyiahf/vczjk/ku5;->OooOOoo:Landroid/os/Bundle;

    iput-object v0, p0, Llyiahf/vczjk/mu5;->OooO0oO:Landroid/os/Bundle;

    new-instance v0, Llyiahf/vczjk/g68;

    new-instance v1, Llyiahf/vczjk/ku7;

    const/4 v2, 0x4

    invoke-direct {v1, p1, v2}, Llyiahf/vczjk/ku7;-><init>(Ljava/lang/Object;I)V

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/g68;-><init>(Llyiahf/vczjk/h68;Llyiahf/vczjk/ku7;)V

    new-instance v1, Llyiahf/vczjk/f68;

    invoke-direct {v1, v0}, Llyiahf/vczjk/f68;-><init>(Llyiahf/vczjk/g68;)V

    iput-object v1, p0, Llyiahf/vczjk/mu5;->OooO0oo:Llyiahf/vczjk/f68;

    new-instance v0, Llyiahf/vczjk/p35;

    const/16 v1, 0x8

    invoke-direct {v0, v1}, Llyiahf/vczjk/p35;-><init>(I)V

    invoke-static {v0}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/wy4;

    invoke-direct {v1, p1}, Llyiahf/vczjk/wy4;-><init>(Llyiahf/vczjk/uy4;)V

    iput-object v1, p0, Llyiahf/vczjk/mu5;->OooOO0:Llyiahf/vczjk/wy4;

    sget-object p1, Llyiahf/vczjk/jy4;->OooOOO:Llyiahf/vczjk/jy4;

    iput-object p1, p0, Llyiahf/vczjk/mu5;->OooOO0O:Llyiahf/vczjk/jy4;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/i68;

    iput-object p1, p0, Llyiahf/vczjk/mu5;->OooOO0o:Llyiahf/vczjk/i68;

    new-instance p1, Llyiahf/vczjk/p35;

    const/16 v0, 0x9

    invoke-direct {p1, v0}, Llyiahf/vczjk/p35;-><init>(I)V

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/mu5;->OooOOO0:Llyiahf/vczjk/sc9;

    return-void
.end method


# virtual methods
.method public final OooO00o()Landroid/os/Bundle;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/mu5;->OooO0OO:Landroid/os/Bundle;

    if-nez v0, :cond_0

    const/4 v0, 0x0

    return-object v0

    :cond_0
    const/4 v1, 0x0

    new-array v2, v1, [Llyiahf/vczjk/xn6;

    invoke-static {v2, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v1

    check-cast v1, [Llyiahf/vczjk/xn6;

    invoke-static {v1}, Llyiahf/vczjk/qqa;->OooOOOo([Llyiahf/vczjk/xn6;)Landroid/os/Bundle;

    move-result-object v1

    invoke-virtual {v1, v0}, Landroid/os/Bundle;->putAll(Landroid/os/Bundle;)V

    return-object v1
.end method

.method public final OooO0O0()V
    .locals 3

    iget-boolean v0, p0, Llyiahf/vczjk/mu5;->OooO:Z

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/mu5;->OooO0oo:Llyiahf/vczjk/f68;

    iget-object v1, v0, Llyiahf/vczjk/f68;->OooO00o:Llyiahf/vczjk/g68;

    invoke-virtual {v1}, Llyiahf/vczjk/g68;->OooO00o()V

    const/4 v1, 0x1

    iput-boolean v1, p0, Llyiahf/vczjk/mu5;->OooO:Z

    iget-object v1, p0, Llyiahf/vczjk/mu5;->OooO0o0:Llyiahf/vczjk/tu5;

    if-eqz v1, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/mu5;->OooO00o:Llyiahf/vczjk/ku5;

    invoke-static {v1}, Llyiahf/vczjk/jp8;->OooOo0O(Llyiahf/vczjk/h68;)V

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/mu5;->OooO0oO:Landroid/os/Bundle;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/f68;->OooO00o(Landroid/os/Bundle;)V

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/mu5;->OooO0Oo:Llyiahf/vczjk/jy4;

    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/mu5;->OooOO0O:Llyiahf/vczjk/jy4;

    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    move-result v1

    iget-object v2, p0, Llyiahf/vczjk/mu5;->OooOO0:Llyiahf/vczjk/wy4;

    if-ge v0, v1, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/mu5;->OooO0Oo:Llyiahf/vczjk/jy4;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/wy4;->OooO0oo(Llyiahf/vczjk/jy4;)V

    return-void

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/mu5;->OooOO0O:Llyiahf/vczjk/jy4;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/wy4;->OooO0oo(Llyiahf/vczjk/jy4;)V

    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v1, p0, Llyiahf/vczjk/mu5;->OooO00o:Llyiahf/vczjk/ku5;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v1

    invoke-interface {v1}, Llyiahf/vczjk/gf4;->OooO0O0()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "("

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v2, p0, Llyiahf/vczjk/mu5;->OooO0o:Ljava/lang/String;

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v2, 0x29

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, " destination="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/mu5;->OooO0O0:Llyiahf/vczjk/av5;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    const-string v1, "toString(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0
.end method
