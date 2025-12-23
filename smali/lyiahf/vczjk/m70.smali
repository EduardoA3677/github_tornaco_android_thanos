.class public abstract Llyiahf/vczjk/m70;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/pj1;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/ak1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ak1;)V
    .locals 1

    const-string v0, "tracker"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/m70;->OooO00o:Llyiahf/vczjk/ak1;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/ara;)Z
    .locals 0

    invoke-interface {p0, p1}, Llyiahf/vczjk/pj1;->OooO0O0(Llyiahf/vczjk/ara;)Z

    move-result p1

    if-eqz p1, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/m70;->OooO00o:Llyiahf/vczjk/ak1;

    invoke-virtual {p1}, Llyiahf/vczjk/ak1;->OooO0oO()Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/m70;->OooO0o0(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final OooO0OO(Llyiahf/vczjk/qk1;)Llyiahf/vczjk/lo0;
    .locals 1

    const-string v0, "constraints"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p1, Llyiahf/vczjk/l70;

    const/4 v0, 0x0

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/l70;-><init>(Llyiahf/vczjk/m70;Llyiahf/vczjk/yo1;)V

    invoke-static {p1}, Llyiahf/vczjk/rs;->OooOO0O(Llyiahf/vczjk/ze3;)Llyiahf/vczjk/lo0;

    move-result-object p1

    return-object p1
.end method

.method public abstract OooO0Oo()I
.end method

.method public abstract OooO0o0(Ljava/lang/Object;)Z
.end method
