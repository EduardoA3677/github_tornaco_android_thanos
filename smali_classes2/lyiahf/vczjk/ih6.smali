.class public abstract Llyiahf/vczjk/ih6;
.super Llyiahf/vczjk/y02;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/hh6;


# instance fields
.field public final OooOo0:Ljava/lang/String;

.field public final OooOo00:Llyiahf/vczjk/hc3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/cm5;Llyiahf/vczjk/hc3;)V
    .locals 3

    const-string v0, "module"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "fqName"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    iget-object v1, p2, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v1}, Llyiahf/vczjk/ic3;->OooO0OO()Z

    move-result v2

    if-eqz v2, :cond_0

    sget-object v1, Llyiahf/vczjk/ic3;->OooO0o0:Llyiahf/vczjk/qt5;

    goto :goto_0

    :cond_0
    invoke-virtual {v1}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v1

    :goto_0
    sget-object v2, Llyiahf/vczjk/sx8;->OooOO0O:Llyiahf/vczjk/up3;

    invoke-direct {p0, p1, v0, v1, v2}, Llyiahf/vczjk/y02;-><init>(Llyiahf/vczjk/v02;Llyiahf/vczjk/ko;Llyiahf/vczjk/qt5;Llyiahf/vczjk/sx8;)V

    iput-object p2, p0, Llyiahf/vczjk/ih6;->OooOo00:Llyiahf/vczjk/hc3;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "package "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p2, " of "

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/ih6;->OooOo0:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public OooO0oO()Llyiahf/vczjk/sx8;
    .locals 1

    sget-object v0, Llyiahf/vczjk/sx8;->OooOO0O:Llyiahf/vczjk/up3;

    return-object v0
.end method

.method public final bridge synthetic OooOO0o()Llyiahf/vczjk/v02;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/ih6;->o0000O0()Llyiahf/vczjk/cm5;

    move-result-object v0

    return-object v0
.end method

.method public final OoooOoO(Llyiahf/vczjk/z02;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    invoke-interface {p1, p0, p2}, Llyiahf/vczjk/z02;->Oooo0OO(Llyiahf/vczjk/ih6;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final o0000O0()Llyiahf/vczjk/cm5;
    .locals 2

    invoke-super {p0}, Llyiahf/vczjk/y02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v0

    const-string v1, "null cannot be cast to non-null type org.jetbrains.kotlin.descriptors.ModuleDescriptor"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/cm5;

    return-object v0
.end method

.method public toString()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ih6;->OooOo0:Ljava/lang/String;

    return-object v0
.end method
