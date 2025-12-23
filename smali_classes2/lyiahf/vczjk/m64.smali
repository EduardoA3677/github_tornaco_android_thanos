.class public final Llyiahf/vczjk/m64;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/tu2;


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()I
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public final OooO0O0(Llyiahf/vczjk/co0;Llyiahf/vczjk/co0;Llyiahf/vczjk/by0;)I
    .locals 6

    const-string v0, "superDescriptor"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "subDescriptor"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v0, p1, Llyiahf/vczjk/eo0;

    const/4 v1, 0x2

    if-eqz v0, :cond_7

    instance-of v0, p2, Llyiahf/vczjk/rf3;

    if-eqz v0, :cond_7

    invoke-static {p2}, Llyiahf/vczjk/hk4;->OooOoOO(Llyiahf/vczjk/v02;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto/16 :goto_2

    :cond_0
    sget v0, Llyiahf/vczjk/lk0;->OooOO0o:I

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/rf3;

    move-object v2, v0

    check-cast v2, Llyiahf/vczjk/w02;

    invoke-virtual {v2}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v3

    const-string v4, "getName(...)"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v3}, Llyiahf/vczjk/lk0;->OooO0O0(Llyiahf/vczjk/qt5;)Z

    move-result v3

    if-nez v3, :cond_1

    sget-object v3, Llyiahf/vczjk/ty8;->OooO00o:Ljava/util/ArrayList;

    invoke-virtual {v2}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v2

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v3, Llyiahf/vczjk/ty8;->OooOO0:Ljava/util/HashSet;

    invoke-virtual {v3, v2}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_1

    goto :goto_2

    :cond_1
    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/eo0;

    invoke-static {v2}, Llyiahf/vczjk/dl6;->OooO(Llyiahf/vczjk/eo0;)Llyiahf/vczjk/eo0;

    move-result-object v2

    instance-of v3, p1, Llyiahf/vczjk/rf3;

    if-eqz v3, :cond_2

    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/rf3;

    goto :goto_0

    :cond_2
    const/4 v4, 0x0

    :goto_0
    if-eqz v4, :cond_3

    invoke-interface {v0}, Llyiahf/vczjk/rf3;->o00oO0o()Z

    move-result v5

    invoke-interface {v4}, Llyiahf/vczjk/rf3;->o00oO0o()Z

    move-result v4

    if-ne v5, v4, :cond_3

    goto :goto_1

    :cond_3
    if-eqz v2, :cond_8

    invoke-interface {v0}, Llyiahf/vczjk/rf3;->o00oO0o()Z

    move-result v4

    if-nez v4, :cond_4

    goto :goto_3

    :cond_4
    :goto_1
    instance-of v4, p3, Llyiahf/vczjk/f64;

    if-eqz v4, :cond_7

    invoke-interface {v0}, Llyiahf/vczjk/rf3;->OooooOO()Llyiahf/vczjk/rf3;

    move-result-object v4

    if-eqz v4, :cond_5

    goto :goto_2

    :cond_5
    if-eqz v2, :cond_7

    invoke-static {p3, v2}, Llyiahf/vczjk/dl6;->OooOO0(Llyiahf/vczjk/by0;Llyiahf/vczjk/eo0;)Z

    move-result p3

    if-eqz p3, :cond_6

    goto :goto_2

    :cond_6
    instance-of p3, v2, Llyiahf/vczjk/rf3;

    if-eqz p3, :cond_8

    if-eqz v3, :cond_8

    check-cast v2, Llyiahf/vczjk/rf3;

    invoke-static {v2}, Llyiahf/vczjk/lk0;->OooO00o(Llyiahf/vczjk/rf3;)Llyiahf/vczjk/rf3;

    move-result-object p3

    if-eqz p3, :cond_8

    invoke-static {v0, v1}, Llyiahf/vczjk/r02;->OooOO0(Llyiahf/vczjk/rf3;I)Ljava/lang/String;

    move-result-object p3

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/rf3;

    invoke-interface {v0}, Llyiahf/vczjk/rf3;->OooO00o()Llyiahf/vczjk/rf3;

    move-result-object v0

    const-string v2, "getOriginal(...)"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0, v1}, Llyiahf/vczjk/r02;->OooOO0(Llyiahf/vczjk/rf3;I)Ljava/lang/String;

    move-result-object v0

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p3

    if-eqz p3, :cond_8

    :cond_7
    :goto_2
    invoke-static {p1, p2}, Llyiahf/vczjk/m6a;->Oooo0OO(Llyiahf/vczjk/co0;Llyiahf/vczjk/co0;)Z

    move-result p1

    if-eqz p1, :cond_9

    :cond_8
    :goto_3
    return v1

    :cond_9
    const/4 p1, 0x3

    return p1
.end method
