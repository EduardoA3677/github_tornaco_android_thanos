.class public final Llyiahf/vczjk/zu6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/jx9;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/kx9;

.field public final OooO0O0:Llyiahf/vczjk/le3;

.field public final OooO0OO:Llyiahf/vczjk/yu6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kx9;Llyiahf/vczjk/le3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/zu6;->OooO00o:Llyiahf/vczjk/kx9;

    iput-object p2, p0, Llyiahf/vczjk/zu6;->OooO0O0:Llyiahf/vczjk/le3;

    new-instance p1, Llyiahf/vczjk/yu6;

    invoke-direct {p1, p0}, Llyiahf/vczjk/yu6;-><init>(Llyiahf/vczjk/zu6;)V

    iput-object p1, p0, Llyiahf/vczjk/zu6;->OooO0OO:Llyiahf/vczjk/yu6;

    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/t02;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public final OooO0O0()Llyiahf/vczjk/wl;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public final OooO0OO()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public final getState()Llyiahf/vczjk/kx9;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zu6;->OooO00o:Llyiahf/vczjk/kx9;

    return-object v0
.end method
