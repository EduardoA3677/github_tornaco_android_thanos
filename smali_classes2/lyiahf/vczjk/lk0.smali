.class public abstract Llyiahf/vczjk/lk0;
.super Llyiahf/vczjk/ty8;
.source "SourceFile"


# static fields
.field public static final synthetic OooOO0o:I


# direct methods
.method public static final OooO00o(Llyiahf/vczjk/rf3;)Llyiahf/vczjk/rf3;
    .locals 2

    const-string v0, "functionDescriptor"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/w02;

    invoke-virtual {v0}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v0

    const-string v1, "getName(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/lk0;->OooO0O0(Llyiahf/vczjk/qt5;)Z

    move-result v0

    if-nez v0, :cond_0

    const/4 p0, 0x0

    return-object p0

    :cond_0
    sget-object v0, Llyiahf/vczjk/tn;->OooOOOo:Llyiahf/vczjk/tn;

    invoke-static {p0, v0}, Llyiahf/vczjk/p72;->OooO0O0(Llyiahf/vczjk/eo0;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/eo0;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/rf3;

    return-object p0
.end method

.method public static OooO0O0(Llyiahf/vczjk/qt5;)Z
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/ty8;->OooO0o0:Ljava/util/Set;

    invoke-interface {v0, p0}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result p0

    return p0
.end method
