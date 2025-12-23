.class public final Llyiahf/vczjk/wd7;
.super Llyiahf/vczjk/yd7;
.source "SourceFile"


# instance fields
.field public final OooO:Z

.field public final OooO0o:Llyiahf/vczjk/wd7;

.field public final OooO0o0:Llyiahf/vczjk/zb7;

.field public final OooO0oO:Llyiahf/vczjk/hy0;

.field public final OooO0oo:Llyiahf/vczjk/yb7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/zb7;Llyiahf/vczjk/rt5;Llyiahf/vczjk/h87;Llyiahf/vczjk/sx8;Llyiahf/vczjk/wd7;)V
    .locals 1

    const-string v0, "classProto"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "nameResolver"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0, p2, p3, p4}, Llyiahf/vczjk/yd7;-><init>(Llyiahf/vczjk/rt5;Llyiahf/vczjk/h87;Llyiahf/vczjk/sx8;)V

    iput-object p1, p0, Llyiahf/vczjk/wd7;->OooO0o0:Llyiahf/vczjk/zb7;

    iput-object p5, p0, Llyiahf/vczjk/wd7;->OooO0o:Llyiahf/vczjk/wd7;

    invoke-virtual {p1}, Llyiahf/vczjk/zb7;->o0OoOo0()I

    move-result p3

    invoke-static {p2, p3}, Llyiahf/vczjk/l4a;->OooOo0O(Llyiahf/vczjk/rt5;I)Llyiahf/vczjk/hy0;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/wd7;->OooO0oO:Llyiahf/vczjk/hy0;

    sget-object p2, Llyiahf/vczjk/c23;->OooO0o:Llyiahf/vczjk/a23;

    invoke-virtual {p1}, Llyiahf/vczjk/zb7;->getFlags()I

    move-result p3

    invoke-virtual {p2, p3}, Llyiahf/vczjk/a23;->OooOO0o(I)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/yb7;

    if-nez p2, :cond_0

    sget-object p2, Llyiahf/vczjk/yb7;->OooOOO0:Llyiahf/vczjk/yb7;

    :cond_0
    iput-object p2, p0, Llyiahf/vczjk/wd7;->OooO0oo:Llyiahf/vczjk/yb7;

    sget-object p2, Llyiahf/vczjk/c23;->OooO0oO:Llyiahf/vczjk/z13;

    invoke-virtual {p1}, Llyiahf/vczjk/zb7;->getFlags()I

    move-result p1

    invoke-virtual {p2, p1}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    iput-boolean p1, p0, Llyiahf/vczjk/wd7;->OooO:Z

    sget-object p1, Llyiahf/vczjk/c23;->OooO0oo:Llyiahf/vczjk/z13;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    return-void
.end method


# virtual methods
.method public final OooO0o0()Llyiahf/vczjk/hc3;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wd7;->OooO0oO:Llyiahf/vczjk/hy0;

    invoke-virtual {v0}, Llyiahf/vczjk/hy0;->OooO00o()Llyiahf/vczjk/hc3;

    move-result-object v0

    return-object v0
.end method
