.class public abstract Llyiahf/vczjk/uz3;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/hc3;

    const-string v1, "kotlin.jvm.JvmInline"

    invoke-direct {v0, v1}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0}, Llyiahf/vczjk/hc3;->OooO0O0()Llyiahf/vczjk/hc3;

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v0}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/hc3;->OooO0OO:Llyiahf/vczjk/hc3;

    invoke-static {v0}, Llyiahf/vczjk/r02;->Oooo00O(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/hc3;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v0}, Llyiahf/vczjk/ic3;->OooO0OO()Z

    return-void
.end method

.method public static final OooO(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/dp8;
    .locals 2

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object p0

    invoke-interface {p0}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object p0

    instance-of v0, p0, Llyiahf/vczjk/by0;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    check-cast p0, Llyiahf/vczjk/by0;

    goto :goto_0

    :cond_0
    move-object p0, v1

    :goto_0
    if-eqz p0, :cond_2

    sget v0, Llyiahf/vczjk/p72;->OooO00o:I

    invoke-interface {p0}, Llyiahf/vczjk/by0;->o0ooOOo()Llyiahf/vczjk/fca;

    move-result-object p0

    instance-of v0, p0, Llyiahf/vczjk/tz3;

    if-eqz v0, :cond_1

    check-cast p0, Llyiahf/vczjk/tz3;

    goto :goto_1

    :cond_1
    move-object p0, v1

    :goto_1
    if-eqz p0, :cond_2

    iget-object p0, p0, Llyiahf/vczjk/tz3;->OooO0O0:Llyiahf/vczjk/pt7;

    check-cast p0, Llyiahf/vczjk/dp8;

    return-object p0

    :cond_2
    return-object v1
.end method

.method public static final OooO00o(Llyiahf/vczjk/eo0;)Z
    .locals 2

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v0, p0, Llyiahf/vczjk/va7;

    if-eqz v0, :cond_1

    check-cast p0, Llyiahf/vczjk/va7;

    check-cast p0, Llyiahf/vczjk/la7;

    invoke-virtual {p0}, Llyiahf/vczjk/la7;->o0000O0()Llyiahf/vczjk/sa7;

    move-result-object p0

    const-string v0, "getCorrespondingProperty(...)"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p0}, Llyiahf/vczjk/co0;->Ooooooo()Llyiahf/vczjk/mp4;

    move-result-object v0

    if-nez v0, :cond_1

    invoke-interface {p0}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v0

    instance-of v1, v0, Llyiahf/vczjk/by0;

    if-eqz v1, :cond_0

    check-cast v0, Llyiahf/vczjk/by0;

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    if-eqz v0, :cond_1

    invoke-interface {v0}, Llyiahf/vczjk/by0;->o0ooOOo()Llyiahf/vczjk/fca;

    move-result-object v0

    if-eqz v0, :cond_1

    invoke-interface {p0}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object p0

    const-string v1, "getName(...)"

    invoke-static {p0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0, p0}, Llyiahf/vczjk/fca;->OooO00o(Llyiahf/vczjk/qt5;)Z

    move-result p0

    const/4 v0, 0x1

    if-ne p0, v0, :cond_1

    return v0

    :cond_1
    const/4 p0, 0x0

    return p0
.end method

.method public static final OooO0O0(Llyiahf/vczjk/v02;)Z
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v0, p0, Llyiahf/vczjk/by0;

    if-eqz v0, :cond_0

    check-cast p0, Llyiahf/vczjk/by0;

    invoke-interface {p0}, Llyiahf/vczjk/by0;->o0ooOOo()Llyiahf/vczjk/fca;

    move-result-object p0

    instance-of p0, p0, Llyiahf/vczjk/tz3;

    if-eqz p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method public static final OooO0OO(Llyiahf/vczjk/uk4;)Z
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object p0

    invoke-interface {p0}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object p0

    if-eqz p0, :cond_0

    invoke-static {p0}, Llyiahf/vczjk/uz3;->OooO0O0(Llyiahf/vczjk/v02;)Z

    move-result p0

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method public static final OooO0Oo(Llyiahf/vczjk/v02;)Z
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v0, p0, Llyiahf/vczjk/by0;

    if-eqz v0, :cond_0

    check-cast p0, Llyiahf/vczjk/by0;

    invoke-interface {p0}, Llyiahf/vczjk/by0;->o0ooOOo()Llyiahf/vczjk/fca;

    move-result-object p0

    instance-of p0, p0, Llyiahf/vczjk/bq5;

    if-eqz p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method public static final OooO0o(Llyiahf/vczjk/v02;)Z
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0}, Llyiahf/vczjk/uz3;->OooO0O0(Llyiahf/vczjk/v02;)Z

    move-result v0

    if-nez v0, :cond_1

    invoke-static {p0}, Llyiahf/vczjk/uz3;->OooO0Oo(Llyiahf/vczjk/v02;)Z

    move-result p0

    if-eqz p0, :cond_0

    goto :goto_0

    :cond_0
    const/4 p0, 0x0

    return p0

    :cond_1
    :goto_0
    const/4 p0, 0x1

    return p0
.end method

.method public static final OooO0o0(Llyiahf/vczjk/ada;)Z
    .locals 3

    invoke-interface {p0}, Llyiahf/vczjk/co0;->Ooooooo()Llyiahf/vczjk/mp4;

    move-result-object v0

    if-nez v0, :cond_3

    invoke-interface {p0}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v0

    instance-of v1, v0, Llyiahf/vczjk/by0;

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    check-cast v0, Llyiahf/vczjk/by0;

    goto :goto_0

    :cond_0
    move-object v0, v2

    :goto_0
    if-eqz v0, :cond_2

    sget v1, Llyiahf/vczjk/p72;->OooO00o:I

    invoke-interface {v0}, Llyiahf/vczjk/by0;->o0ooOOo()Llyiahf/vczjk/fca;

    move-result-object v0

    instance-of v1, v0, Llyiahf/vczjk/tz3;

    if-eqz v1, :cond_1

    check-cast v0, Llyiahf/vczjk/tz3;

    goto :goto_1

    :cond_1
    move-object v0, v2

    :goto_1
    if-eqz v0, :cond_2

    iget-object v2, v0, Llyiahf/vczjk/tz3;->OooO00o:Llyiahf/vczjk/qt5;

    :cond_2
    invoke-interface {p0}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object p0

    invoke-static {v2, p0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p0

    if-eqz p0, :cond_3

    const/4 p0, 0x1

    return p0

    :cond_3
    const/4 p0, 0x0

    return p0
.end method

.method public static final OooO0oO(Llyiahf/vczjk/uk4;)Z
    .locals 0

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object p0

    invoke-interface {p0}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object p0

    if-eqz p0, :cond_0

    invoke-static {p0}, Llyiahf/vczjk/uz3;->OooO0o(Llyiahf/vczjk/v02;)Z

    move-result p0

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method public static final OooO0oo(Llyiahf/vczjk/uk4;)Z
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-static {v0}, Llyiahf/vczjk/uz3;->OooO0Oo(Llyiahf/vczjk/v02;)Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-static {p0}, Llyiahf/vczjk/l5a;->OooO0o0(Llyiahf/vczjk/uk4;)Z

    move-result p0

    if-nez p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method
